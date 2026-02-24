"""Search Service FastAPI application."""

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
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

from services.search.config import config
from services.search.indexer import SearchIndexer
from services.search.query import parse_query, build_search_filters

setup_logging(service_name="search")
logger = get_context_logger("search.app")


# Request/Response models
class SearchResponse(BaseModel):
    """Search response."""
    items: list[dict]
    total: int
    page: int
    per_page: int
    total_pages: int


class SampleDetail(BaseModel):
    """Sample detail response."""
    sample_sha256: str
    tenant_id: str
    file_type: str
    findings: list[dict]
    iocs: list[dict]
    analyzer_names: list[str]
    tags: list[str]
    verdict: str | None
    score: int | None
    created_at: str
    updated_at: str


class IOCIntelResponse(BaseModel):
    """IOC intelligence response."""
    ioc_value: str
    ioc_type: str
    samples: list[str]
    tenants: list[str]
    first_seen: str
    last_seen: str
    total_sightings: int


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


# Database dependency
def get_db() -> Session:
    """Get database session."""
    from services.search.database import get_session
    return get_session()


# Auth dependency
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


def require_viewer(auth: AuthContext = Depends(get_auth)) -> AuthContext:
    """Require viewer role."""
    try:
        require_role(auth, Role.VIEWER)
    except ForbiddenError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    return auth


# Create indexer
def get_indexer(db: Session = Depends(get_db)) -> SearchIndexer:
    """Get search indexer."""
    from services.search.database import get_session_factory
    return SearchIndexer(get_session_factory())


# Create FastAPI app
def create_app() -> FastAPI:
    """Create FastAPI application."""
    app = FastAPI(
        title="SCARABEO Search Service",
        description="Search and intelligence service",
        version="1.0.0",
    )

    app.add_middleware(MetricsMiddleware, service_name="search")

    app.get("/healthz")(health_check)
    app.get("/readyz")(ready_check)
    app.get("/metrics")(metrics_endpoint)
    app.get("/search")(search_samples)
    app.get("/search/sample/{sha256}")(get_sample)
    app.get("/search/ioc/{ioc_value}")(search_ioc)
    app.get("/search/recent")(get_recent)
    app.get("/intel/ioc/{ioc_value}")(get_ioc_intel)

    return app


def health_check() -> HealthResponse:
    """Liveness health check."""
    return HealthResponse(
        status="healthy",
        service="search",
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

    all_ok = all(v == "ok" for v in checks.values())
    return ReadyResponse(
        status="ready" if all_ok else "not_ready",
        service="search",
        checks=checks,
    )


def metrics_endpoint() -> PlainTextResponse:
    """Prometheus metrics endpoint."""
    metrics = get_metrics_collector()
    return PlainTextResponse(metrics.get_metrics(), media_type=metrics.get_content_type())


def search_samples(
    q: str = Query(default="", description="Search query"),
    file_type: str | None = Query(None),
    verdict: str | None = Query(None),
    tag: str | None = Query(None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    auth: AuthContext = Depends(require_viewer),
    indexer: SearchIndexer = Depends(get_indexer),
) -> SearchResponse:
    """
    Search samples.

    Query supports filters:
    - type:<file_type>
    - verdict:<verdict>
    - tag:<tag>
    - severity:<severity>
    """
    metrics = get_metrics_collector()
    metrics.record_request(
        route="/search",
        method="GET",
        status=200,
        duration=0,
        service="search",
    )

    # Parse query
    parsed = parse_query(q)

    # Use explicit params if provided
    if file_type:
        parsed.file_type = file_type
    if verdict:
        parsed.verdict = verdict
    if tag:
        parsed.tag = tag

    results, total = indexer.search(
        tenant_id=auth.tenant_id,
        query=parsed.text,
        file_type=parsed.file_type,
        verdict=parsed.verdict,
        tag=parsed.tag,
        page=page,
        per_page=min(per_page, config.MAX_PAGE_SIZE),
    )

    total_pages = (total + per_page - 1) // per_page if total > 0 else 1

    return SearchResponse(
        items=results,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
    )


def get_sample(
    sha256: str,
    auth: AuthContext = Depends(require_viewer),
    indexer: SearchIndexer = Depends(get_indexer),
) -> SampleDetail:
    """Get sample details by SHA256."""
    result = indexer.get_sample(auth.tenant_id, sha256)

    if not result:
        raise HTTPException(status_code=404, detail="Sample not found")

    return SampleDetail(**result)


def search_ioc(
    ioc_value: str,
    auth: AuthContext = Depends(require_viewer),
    indexer: SearchIndexer = Depends(get_indexer),
) -> dict:
    """Search for samples containing specific IOC."""
    db = indexer.db_session_factory()
    try:
        from services.search.models import SearchIndex
        from sqlalchemy import select

        # Search in IOC field
        stmt = select(SearchIndex).where(
            SearchIndex.tenant_id == auth.tenant_id,
            SearchIndex.iocs.cast(str).like(f"%{ioc_value}%"),
        ).limit(100)

        results = db.execute(stmt).scalars().all()

        return {
            "ioc_value": ioc_value,
            "samples": [
                {
                    "sha256": r.sample_sha256,
                    "file_type": r.file_type,
                    "created_at": r.created_at.isoformat(),
                }
                for r in results
            ],
            "total": len(results),
        }
    finally:
        db.close()


def get_recent(
    limit: int = Query(default=20, ge=1, le=100),
    auth: AuthContext = Depends(require_viewer),
    indexer: SearchIndexer = Depends(get_indexer),
) -> list[dict]:
    """Get recent samples."""
    return indexer.get_recent(auth.tenant_id, limit=limit)


def get_ioc_intel(
    ioc_value: str,
    auth: AuthContext = Depends(require_viewer),
    db: Session = Depends(get_db),
) -> IOCIntelResponse:
    """Get IOC intelligence data."""
    from services.search.models import IOCSighting
    from sqlalchemy import select, func

    # Get all sightings for this IOC value
    stmt = select(IOCSighting).where(
        IOCSighting.ioc_value == ioc_value,
        IOCSighting.tenant_id == auth.tenant_id,
    ).order_by(IOCSighting.first_seen.desc())

    sightings = db.execute(stmt).scalars().all()

    if not sightings:
        raise HTTPException(status_code=404, detail="IOC not found")

    # Aggregate data
    samples = list(set(s.sample_sha256 for s in sightings))
    tenants = list(set(s.tenant_id for s in sightings))
    first_seen = min(s.first_seen for s in sightings)
    last_seen = max(s.last_seen for s in sightings)
    total_count = sum(s.sighting_count for s in sightings)

    return IOCIntelResponse(
        ioc_value=ioc_value,
        ioc_type=sightings[0].ioc_type,
        samples=samples[:100],  # Limit
        tenants=tenants,
        first_seen=first_seen.isoformat(),
        last_seen=last_seen.isoformat(),
        total_sightings=total_count,
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
