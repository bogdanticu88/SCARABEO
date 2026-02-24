"""Orchestrator Service FastAPI application with enterprise hardening."""

import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import generate_latest
from pydantic import BaseModel
from sqlalchemy.orm import Session

from scarabeo.auth import (
    AuthContext,
    Role,
    authenticate_from_headers,
    require_role,
    AuthError,
    ForbiddenError,
)
from scarabeo.logging import setup_logging, get_context_logger
from scarabeo.metrics import get_metrics_collector, MetricsMiddleware

from services.orchestrator.config import settings
from services.orchestrator.database import get_db
from services.orchestrator.models import AuditAction, JobStatus
from services.orchestrator.service import (
    create_audit_log,
    get_job_by_id,
    retry_job,
)

setup_logging(service_name="orchestrator")
logger = get_context_logger("orchestrator.app")


class JobResponse(BaseModel):
    """Job details response."""
    id: str
    sample_id: str
    sample_sha256: str
    tenant_id: str
    pipeline_name: str
    pipeline_hash: str
    status: str
    priority: str
    timeout_seconds: int | None
    result: str | None
    error_message: str | None
    created_at: str
    started_at: str | None
    completed_at: str | None


class RetryJobResponse(BaseModel):
    """Retry job response."""
    original_job_id: str
    new_job_id: str
    status: str


class ErrorResponse(BaseModel):
    """Error response."""
    error: str
    message: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    service: str
    timestamp: str


class ReadyResponse(BaseModel):
    """Readiness check response."""
    status: str
    service: str
    checks: dict


def get_auth(
    x_tenant_id: str | None = Header(None, alias="X-Tenant-Id"),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
    x_role: str | None = Header(None, alias="X-Role"),
) -> AuthContext:
    """Get auth context from headers."""
    headers = {"X-Tenant-Id": x_tenant_id, "X-User-Id": x_user_id, "X-Role": x_role}
    try:
        return authenticate_from_headers(headers)
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


def require_admin(auth: AuthContext = Depends(get_auth)) -> AuthContext:
    """Require admin role."""
    try:
        require_role(auth, Role.ADMIN)
    except ForbiddenError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    return auth


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler."""
    logger.info("Orchestrator service starting")
    yield
    logger.info("Orchestrator service shutting down")


def create_app() -> FastAPI:
    """Create FastAPI application."""
    app = FastAPI(
        title="Scarabeo Orchestrator Service",
        description="Job orchestration and worker dispatch",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(MetricsMiddleware, service_name="orchestrator")

    app.get("/healthz")(health_check)
    app.get("/readyz")(ready_check)
    app.get("/metrics")(metrics_endpoint)
    app.get("/jobs/{job_id}")(get_job)
    app.post("/jobs/{job_id}/retry")(retry_job_endpoint)

    return app


def health_check() -> HealthResponse:
    """Liveness health check."""
    return HealthResponse(
        status="healthy",
        service="orchestrator",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def ready_check(db: Session = Depends(get_db)) -> ReadyResponse:
    """Readiness check."""
    checks = {}
    try:
        db.execute("SELECT 1")
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {e}"

    try:
        from scarabeo.rate_limit import get_redis_client
        redis = get_redis_client()
        redis.ping()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {e}"

    all_ok = all(v == "ok" for v in checks.values())
    return ReadyResponse(
        status="ready" if all_ok else "not_ready",
        service="orchestrator",
        checks=checks,
    )


def metrics_endpoint() -> PlainTextResponse:
    """Prometheus metrics endpoint."""
    metrics = get_metrics_collector()
    return PlainTextResponse(metrics.get_metrics(), media_type=metrics.get_content_type())


def get_job(job_id: str, db: Session = Depends(get_db)) -> JobResponse:
    """Get job by ID."""
    job = get_job_by_id(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

    return JobResponse(
        id=str(job.id),
        sample_id=str(job.sample_id),
        sample_sha256=job.sample.sha256,
        tenant_id=job.sample.tenant_id,
        pipeline_name=job.pipeline_name,
        pipeline_hash=job.pipeline_hash,
        status=job.status.value,
        priority=job.priority,
        timeout_seconds=job.timeout_seconds,
        result=job.result,
        error_message=job.error_message,
        created_at=job.created_at.isoformat(),
        started_at=job.started_at.isoformat() if job.started_at else None,
        completed_at=job.completed_at.isoformat() if job.completed_at else None,
    )


def retry_job_endpoint(
    job_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_admin),
) -> RetryJobResponse:
    """Retry a failed job. Requires admin role."""
    start_time = time.time()
    metrics = get_metrics_collector()

    job = get_job_by_id(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

    if job.status != JobStatus.FAILED:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot retry job with status {job.status.value}",
        )

    new_job = retry_job(db, job)

    duration = time.time() - start_time
    metrics.record_job(status="retried", pipeline=job.pipeline_name, duration=duration, service="orchestrator")

    logger.info(
        "Job retry initiated",
        extra={
            "tenant_id": auth.tenant_id,
            "user_id": auth.user_id,
            "original_job_id": job_id,
            "new_job_id": str(new_job.id),
            "event": "job_retry",
        },
    )

    return RetryJobResponse(
        original_job_id=job_id,
        new_job_id=str(new_job.id),
        status="queued",
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register exception handlers."""

    @app.exception_handler(HTTPException)
    async def http_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "http_error", "message": str(exc.detail)},
        )

    @app.exception_handler(Exception)
    async def general_handler(request: Request, exc: Exception):
        logger.exception(f"Unhandled exception: {exc}")
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "message": "An unexpected error occurred"},
        )


app = create_app()
register_exception_handlers(app)
