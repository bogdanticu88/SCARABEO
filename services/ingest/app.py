"""Ingest Service FastAPI application with enterprise hardening."""

import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from scarabeo.auth import (
    AuthContext,
    Role,
    authenticate_from_headers,
    require_role,
    AuthError,
    ForbiddenError,
)
from scarabeo.rate_limit import get_rate_limiter, RateLimitError
from scarabeo.logging import setup_logging, get_context_logger
from scarabeo.metrics import get_metrics_collector, MetricsMiddleware

from services.ingest.config import settings
from services.ingest.database import get_db
from services.ingest.models import JobStatus
from services.ingest.service import (
    get_latest_job_for_sample,
    get_sample_by_sha256,
    list_samples as list_samples_service,
    upload_sample,
)

# Setup structured logging
setup_logging(service_name="ingest")
logger = get_context_logger("ingest.app")


# Request/Response models
class SampleResponse(BaseModel):
    """Sample details response."""
    sha256: str
    md5: str | None = None
    sha1: str | None = None
    filename: str
    size_bytes: int
    mime_type: str | None = None
    file_type: str
    submitted_at: datetime
    status: str | None = None
    tags: list[str] = Field(default_factory=list)


class SampleSummary(BaseModel):
    """Sample summary for list response."""
    sha256: str
    filename: str
    size_bytes: int
    submitted_at: datetime
    status: str | None = None
    verdict: str | None = None
    score: int | None = None


class Pagination(BaseModel):
    """Pagination metadata."""
    page: int
    per_page: int
    total_items: int
    total_pages: int
    has_next: bool
    has_prev: bool


class ListSamplesResponse(BaseModel):
    """Paginated samples list response."""
    items: list[SampleSummary]
    pagination: Pagination


class SubmitSampleResponse(BaseModel):
    """Sample submission response."""
    submission_id: str
    sha256: str
    status: str
    estimated_time: int | None = None


class SimilarSample(BaseModel):
    """Single similarity match."""
    sha256: str
    algorithm: str
    score: int


class SimilarSamplesResponse(BaseModel):
    """Response for similar-samples query."""
    sha256: str
    algorithm: str
    matches: list[SimilarSample]
    total: int


class AIAnalysisResponse(BaseModel):
    """AI-generated analysis response (summary or remediation)."""
    sha256: str
    narrative: str | None = None
    remediation: str | None = None
    generated_at: str | None = None
    model: str | None = None
    cached: bool


class FindingExplanationResponse(BaseModel):
    """AI explanation for a single finding."""
    finding_id: str
    explanation: str
    model: str


class ErrorResponse(BaseModel):
    """Error response."""
    error: str
    message: str
    details: dict | None = None


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


# Auth dependency
def get_auth(
    x_tenant_id: str | None = Header(None, alias="X-Tenant-Id"),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
    x_role: str | None = Header(None, alias="X-Role"),
) -> AuthContext:
    """Get auth context from headers."""
    headers = {
        "X-Tenant-Id": x_tenant_id,
        "X-User-Id": x_user_id,
        "X-Role": x_role,
    }
    try:
        return authenticate_from_headers(headers)
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


def require_analyst(auth: AuthContext = Depends(get_auth)) -> AuthContext:
    """Require analyst role."""
    try:
        require_role(auth, Role.ANALYST)
    except ForbiddenError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    return auth


def require_admin(auth: AuthContext = Depends(get_auth)) -> AuthContext:
    """Require admin role."""
    try:
        require_role(auth, Role.ADMIN)
    except ForbiddenError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    return auth


# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler."""
    logger.info("Ingest service starting")
    yield
    logger.info("Ingest service shutting down")


# Create FastAPI app
def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="Scarabeo Ingest Service",
        description="Sample ingestion and job queuing service",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Add metrics middleware
    app.add_middleware(MetricsMiddleware, service_name="ingest")

    # Register routes
    app.get("/healthz")(health_check)
    app.get("/readyz")(ready_check)
    app.get("/metrics")(metrics_endpoint)
    app.post("/samples")(submit_sample)
    app.get("/samples")(list_samples)
    app.get("/samples/{sha256}")(get_sample)
    app.get("/samples/{sha256}/report")(get_sample_report)
    app.get("/samples/{sha256}/similar")(get_sample_similar)
    app.get("/samples/{sha256}/ai/summary")(get_ai_summary)
    app.post("/samples/{sha256}/ai/explain")(explain_finding_endpoint)
    app.post("/samples/{sha256}/ai/remediation")(get_ai_remediation)

    # Include review workflow router
    from services.api.review import router as review_router
    app.include_router(review_router)

    # Include clusters router
    from services.api.clusters import router as clusters_router
    app.include_router(clusters_router)

    return app


# Health endpoints
def health_check() -> HealthResponse:
    """Liveness health check."""
    return HealthResponse(
        status="healthy",
        service="ingest",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def ready_check(db: Session = Depends(get_db)) -> ReadyResponse:
    """Readiness check with dependency verification."""
    checks = {}

    # Check database
    try:
        db.execute("SELECT 1")
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {e}"

    # Check Redis
    try:
        from scarabeo.rate_limit import get_redis_client
        redis_client = get_redis_client()
        redis_client.ping()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {e}"

    # Check S3
    try:
        from services.ingest.storage import get_storage_client
        storage = get_storage_client()
        storage.ensure_bucket_exists()
        checks["s3"] = "ok"
    except Exception as e:
        checks["s3"] = f"error: {e}"

    all_ok = all(v == "ok" for v in checks.values())

    return ReadyResponse(
        status="ready" if all_ok else "not_ready",
        service="ingest",
        checks=checks,
    )


def metrics_endpoint() -> PlainTextResponse:
    """Prometheus metrics endpoint."""
    metrics = get_metrics_collector()
    return PlainTextResponse(
        metrics.get_metrics(),
        media_type=metrics.get_content_type(),
    )


# Routes
def submit_sample(
    request: Request,
    auth: AuthContext = Depends(require_analyst),
    file: UploadFile = File(..., description="Sample file to analyze"),
    priority: str = Form(default="normal", description="Analysis priority"),
    timeout: int | None = Form(default=None, description="Analysis timeout in seconds"),
    db: Session = Depends(get_db),
) -> SubmitSampleResponse:
    """Submit a sample for analysis. Requires analyst or admin role."""
    start_time = time.time()
    metrics = get_metrics_collector()

    # Check rate limit
    rate_limiter = get_rate_limiter()
    allowed, limit_info = rate_limiter.check_upload_limit(auth.tenant_id)

    if not allowed:
        metrics.record_rate_limit_hit(auth.tenant_id, "uploads", "ingest")
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "message": f"Upload limit exceeded: {limit_info['limit']} per minute",
                "retry_after": limit_info.get("retry_after", 60),
            },
        )

    # Validate file size
    if file.size is not None and file.size > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File size exceeds maximum of {settings.MAX_UPLOAD_SIZE_MB}MB",
        )

    # Read file
    try:
        file_content = file.file.read()
        file_size = len(file_content)
    except Exception as e:
        logger.error(f"Failed to read uploaded file: {e}", extra={"tenant_id": auth.tenant_id})
        raise HTTPException(status_code=400, detail="Failed to read uploaded file") from e

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file not allowed")

    # Validate priority
    valid_priorities = ["low", "normal", "high", "critical"]
    if priority not in valid_priorities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid priority. Must be one of: {valid_priorities}",
        )

    # Validate timeout
    if timeout is not None and (timeout < 60 or timeout > 3600):
        raise HTTPException(status_code=400, detail="Timeout must be between 60 and 3600 seconds")

    from io import BytesIO
    file_obj = BytesIO(file_content)

    try:
        sample, job = upload_sample(
            db=db,
            file_obj=file_obj,
            filename=file.filename or "unnamed",
            tenant_id=auth.tenant_id,
            file_size=file_size,
            priority=priority,
            timeout_seconds=timeout,
        )

        # Record metrics
        duration = time.time() - start_time
        metrics.record_upload(
            status=200,
            file_type=sample.file_type,
            size_bytes=file_size,
            service="ingest",
        )

        logger.info(
            "Sample submitted",
            extra={
                "tenant_id": auth.tenant_id,
                "user_id": auth.user_id,
                "sha256": sample.sha256,
                "job_id": str(job.id),
                "event": "sample_upload",
            },
        )

        return SubmitSampleResponse(
            submission_id=str(job.id),
            sha256=sample.sha256,
            status="queued",
            estimated_time=300,
        )

    except Exception as e:
        logger.exception(f"Failed to process sample upload: {e}")
        metrics.record_upload(status=500, file_type="unknown", size_bytes=file_size, service="ingest")
        raise HTTPException(status_code=500, detail="Failed to process sample upload") from e


def list_samples(
    auth: AuthContext = Depends(get_auth),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    status_filter: str | None = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
) -> ListSamplesResponse:
    """List samples. Requires viewer role or higher."""
    samples, total = list_samples_service(
        db=db,
        tenant_id=auth.tenant_id,
        page=page,
        per_page=per_page,
        status=status_filter,
    )

    total_pages = (total + per_page - 1) // per_page if total > 0 else 1

    items = []
    for sample in samples:
        job = get_latest_job_for_sample(db, sample.id)
        status_value = job.status.value.lower() if job else None
        items.append(
            SampleSummary(
                sha256=sample.sha256,
                filename=sample.filename,
                size_bytes=sample.size_bytes,
                submitted_at=sample.created_at,
                status=status_value,
            )
        )

    return ListSamplesResponse(
        items=items,
        pagination=Pagination(
            page=page,
            per_page=per_page,
            total_items=total,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1,
        ),
    )


def get_sample(
    sha256: str,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> SampleResponse:
    """Get sample details. Requires viewer role or higher."""
    sample = get_sample_by_sha256(db=db, sha256=sha256, tenant_id=auth.tenant_id)

    if not sample:
        raise HTTPException(status_code=404, detail=f"Sample not found: {sha256}")

    job = get_latest_job_for_sample(db, sample.id)
    status_value = job.status.value.lower() if job else None

    return SampleResponse(
        sha256=sample.sha256,
        md5=sample.md5,
        sha1=sample.sha1,
        filename=sample.filename,
        size_bytes=sample.size_bytes,
        mime_type=None,
        file_type=sample.file_type,
        submitted_at=sample.created_at,
        status=status_value,
    )


def get_sample_report(
    sha256: str,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> Response:
    """Get analysis report. Requires viewer role or higher."""
    sample = get_sample_by_sha256(db=db, sha256=sha256, tenant_id=auth.tenant_id)

    if not sample:
        raise HTTPException(status_code=404, detail=f"Sample not found: {sha256}")

    job = get_latest_job_for_sample(db, sample.id)

    if not job:
        raise HTTPException(status_code=404, detail="No analysis job found")

    if job.status == JobStatus.QUEUED:
        return JSONResponse(
            status_code=425,
            content={"status": "queued", "message": "Analysis queued", "progress": 0},
        )

    if job.status == JobStatus.RUNNING:
        return JSONResponse(
            status_code=425,
            content={"status": "processing", "message": "Analysis in progress", "progress": 50},
        )

    if job.status == JobStatus.FAILED:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {job.error_message}")

    from services.ingest.storage import get_storage_client, S3StorageError
    storage = get_storage_client()
    report_path = f"samples/{auth.tenant_id}/{sha256}/reports/{job.pipeline_hash}/report.json"

    try:
        if not storage.file_exists(report_path):
            raise HTTPException(status_code=404, detail="Report not found")
        report_data = storage.download_json(report_path)
        return JSONResponse(content=report_data)
    except S3StorageError as e:
        logger.error(f"Failed to retrieve report: {e}")
        raise HTTPException(status_code=404, detail="Report not available") from e


def get_sample_similar(
    sha256: str,
    auth: AuthContext = Depends(get_auth),
    algorithm: str = Query(
        default="tlsh",
        pattern="^(tlsh|ssdeep|imphash)$",
        description="Similarity algorithm: tlsh, ssdeep, or imphash",
    ),
    limit: int = Query(default=20, ge=1, le=100, description="Maximum matches to return"),
    db: Session = Depends(get_db),
) -> SimilarSamplesResponse:
    """Find samples similar to the given sha256. Requires viewer role or higher."""
    sample = get_sample_by_sha256(db=db, sha256=sha256, tenant_id=auth.tenant_id)
    if not sample:
        raise HTTPException(status_code=404, detail=f"Sample not found: {sha256}")

    from scarabeo.fingerprint import find_similar

    try:
        matches = find_similar(
            db,
            sha256=sha256,
            tenant_id=auth.tenant_id,
            algorithm=algorithm,
            limit=limit,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    return SimilarSamplesResponse(
        sha256=sha256,
        algorithm=algorithm,
        matches=[SimilarSample(**m) for m in matches],
        total=len(matches),
    )


def _load_report_for_sample(sha256: str, auth: AuthContext, db) -> dict:
    """Load report JSON from S3 for a given sample. Raises HTTPException on any failure."""
    from services.ingest.storage import get_storage_client, S3StorageError

    sample = get_sample_by_sha256(db=db, sha256=sha256, tenant_id=auth.tenant_id)
    if not sample:
        raise HTTPException(status_code=404, detail=f"Sample not found: {sha256}")

    job = get_latest_job_for_sample(db, sample.id)
    if not job or job.status != JobStatus.SUCCEEDED:
        raise HTTPException(status_code=404, detail="Completed report not available")

    storage = get_storage_client()
    report_path = f"samples/{auth.tenant_id}/{sha256}/reports/{job.pipeline_hash}/report.json"
    try:
        if not storage.file_exists(report_path):
            raise HTTPException(status_code=404, detail="Report file not found")
        return storage.download_json(report_path)
    except S3StorageError as e:
        logger.error(f"Failed to load report for AI endpoint: {e}")
        raise HTTPException(status_code=404, detail="Report not available") from e


def _get_ollama_client():
    """Return an OllamaClient based on ingest config settings."""
    from scarabeo.llm import OllamaClient
    return OllamaClient(settings.OLLAMA_URL, settings.OLLAMA_MODEL, settings.OLLAMA_TIMEOUT)


def get_ai_summary(
    sha256: str,
    auth: AuthContext = Depends(get_auth),
    db=Depends(get_db),
) -> AIAnalysisResponse:
    """
    Return AI-generated narrative summary for a sample report.

    Returns cached result if the report already contains ai_analysis,
    otherwise generates fresh output from Ollama. Returns 503 if Ollama
    is unreachable and no cached result exists.
    """
    report = _load_report_for_sample(sha256, auth, db)

    cached = report.get("ai_analysis")
    if cached:
        return AIAnalysisResponse(
            sha256=sha256,
            narrative=cached.get("narrative"),
            remediation=cached.get("remediation"),
            generated_at=cached.get("generated_at"),
            model=cached.get("model"),
            cached=True,
        )

    client = _get_ollama_client()
    if not client.is_available():
        raise HTTPException(
            status_code=503,
            detail="AI service (Ollama) is not available. Submit the sample for re-analysis with OLLAMA_ENABLED=true, or start Ollama locally.",
        )

    from scarabeo.ai import enrich_report_with_ai
    analysis = enrich_report_with_ai(report, client)
    return AIAnalysisResponse(
        sha256=sha256,
        narrative=analysis["narrative"],
        remediation=analysis["remediation"],
        generated_at=analysis["generated_at"],
        model=analysis["model"],
        cached=False,
    )


def explain_finding_endpoint(
    sha256: str,
    body: dict,
    auth: AuthContext = Depends(get_auth),
    db=Depends(get_db),
) -> FindingExplanationResponse:
    """
    Generate a plain-English explanation for a specific finding within a report.

    Request body: {"finding_id": "<id>"}
    Always generates fresh output — explanations are not cached.
    """
    finding_id = body.get("finding_id")
    if not finding_id:
        raise HTTPException(status_code=422, detail="finding_id is required")

    report = _load_report_for_sample(sha256, auth, db)

    finding = next((f for f in report.get("findings", []) if f.get("id") == finding_id), None)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")

    client = _get_ollama_client()
    if not client.is_available():
        raise HTTPException(status_code=503, detail="AI service (Ollama) is not available")

    from scarabeo.ai import explain_finding
    explanation = explain_finding(finding, client)
    return FindingExplanationResponse(
        finding_id=finding_id,
        explanation=explanation,
        model=client.model,
    )


def get_ai_remediation(
    sha256: str,
    auth: AuthContext = Depends(get_auth),
    db=Depends(get_db),
) -> AIAnalysisResponse:
    """
    Return AI-generated remediation advice for a sample report.

    Returns cached remediation if present in the stored report, otherwise
    generates fresh output. Returns 503 if Ollama is unreachable and no
    cached result exists.
    """
    report = _load_report_for_sample(sha256, auth, db)

    cached = report.get("ai_analysis", {})
    if cached.get("remediation"):
        return AIAnalysisResponse(
            sha256=sha256,
            remediation=cached.get("remediation"),
            generated_at=cached.get("generated_at"),
            model=cached.get("model"),
            cached=True,
        )

    client = _get_ollama_client()
    if not client.is_available():
        raise HTTPException(status_code=503, detail="AI service (Ollama) is not available")

    from scarabeo.ai import suggest_remediation
    from datetime import datetime, timezone
    remediation = suggest_remediation(report, client)
    return AIAnalysisResponse(
        sha256=sha256,
        remediation=remediation,
        generated_at=datetime.now(timezone.utc).isoformat(),
        model=client.model,
        cached=False,
    )


# Exception handlers
def register_exception_handlers(app: FastAPI) -> None:
    """Register exception handlers."""

    @app.exception_handler(HTTPException)
    async def http_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "http_error", "message": str(exc.detail)},
        )

    @app.exception_handler(AuthError)
    async def auth_handler(request: Request, exc: AuthError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "auth_error", "message": exc.message},
        )

    @app.exception_handler(Exception)
    async def general_handler(request: Request, exc: Exception):
        logger.exception(f"Unhandled exception: {exc}")
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "message": "An unexpected error occurred"},
        )


# Create app
app = create_app()
register_exception_handlers(app)
