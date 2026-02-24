"""Web Console - Lightweight read-only UI for SCARABEO."""

import logging
from datetime import datetime, timezone

import requests
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from scarabeo.auth import authenticate_from_headers, Role, require_role, AuthError, ForbiddenError
from scarabeo.logging import setup_logging
from services.web.config import config

setup_logging(service_name="web")
logger = logging.getLogger(__name__)

templates = Jinja2Templates(directory="services/web/templates")

app = FastAPI(
    title="SCARABEO Web Console",
    description="Read-only web console for SCARABEO",
    version="1.0.0",
)


# Auth dependency
def get_auth(
    x_tenant_id: str | None = Header(None, alias="X-Tenant-Id"),
    x_user_id: str | None = Header(None, alias="X-User-Id"),
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict:
    """Get auth context from headers."""
    headers = {"X-Tenant-Id": x_tenant_id, "X-User-Id": x_user_id, "X-Role": x_role}
    try:
        auth = authenticate_from_headers(headers)
        return {
            "tenant_id": auth.tenant_id,
            "user_id": auth.user_id,
            "role": auth.role.value,
        }
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


def require_viewer(auth: dict = Depends(get_auth)) -> dict:
    """Require viewer role."""
    try:
        role = Role(auth["role"])
        if role not in [Role.VIEWER, Role.ANALYST, Role.ADMIN]:
            raise ForbiddenError("Insufficient permissions")
    except (KeyError, ValueError, ForbiddenError) as e:
        raise HTTPException(status_code=403, detail=str(e))
    return auth


@app.get("/", response_class=HTMLResponse)
async def home(
    request: Request,
    auth: dict = Depends(require_viewer),
    limit: int = Query(default=20, ge=1, le=100),
):
    """Home page - recent samples."""
    import requests

    try:
        # Get recent samples from search API
        response = requests.get(
            f"{config.SEARCH_API_URL}/search/recent",
            headers={
                "X-Tenant-Id": auth["tenant_id"],
                "X-User-Id": auth["user_id"],
                "X-Role": auth["role"],
            },
            params={"limit": limit},
            timeout=10,
        )
        response.raise_for_status()
        samples = response.json()
    except Exception as e:
        logger.error(f"Failed to fetch recent samples: {e}")
        samples = []

    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "samples": samples,
            "tenant_id": auth["tenant_id"],
            "user_id": auth["user_id"],
        },
    )


@app.get("/sample/{sha256}", response_class=HTMLResponse)
async def sample_detail(
    sha256: str,
    request: Request,
    auth: dict = Depends(require_viewer),
):
    """Sample detail page."""
    import requests

    try:
        # Get sample from ingest API
        response = requests.get(
            f"{config.INGEST_API_URL}/samples/{sha256}",
            headers={
                "X-Tenant-Id": auth["tenant_id"],
                "X-User-Id": auth["user_id"],
                "X-Role": auth["role"],
            },
            timeout=10,
        )
        response.raise_for_status()
        sample = response.json()
    except Exception as e:
        logger.error(f"Failed to fetch sample: {e}")
        raise HTTPException(status_code=404, detail="Sample not found")

    try:
        # Get clusters for sample
        response = requests.get(
            f"{config.INGEST_API_URL}/clusters/samples/{sha256}/clusters",
            headers={
                "X-Tenant-Id": auth["tenant_id"],
                "X-User-Id": auth["user_id"],
                "X-Role": auth["role"],
            },
            timeout=10,
        )
        clusters = response.json().get("clusters", []) if response.status_code == 200 else []
    except Exception:
        clusters = []

    return templates.TemplateResponse(
        "sample.html",
        {
            "request": request,
            "sample": sample,
            "clusters": clusters,
            "tenant_id": auth["tenant_id"],
            "user_id": auth["user_id"],
        },
    )


@app.get("/search", response_class=HTMLResponse)
async def search(
    request: Request,
    auth: dict = Depends(require_viewer),
    q: str = Query(default=""),
    page: int = Query(default=1, ge=1),
):
    """Search page."""
    import requests

    results = []
    total = 0
    total_pages = 0

    if q:
        try:
            response = requests.get(
                f"{config.SEARCH_API_URL}/search",
                headers={
                    "X-Tenant-Id": auth["tenant_id"],
                    "X-User-Id": auth["user_id"],
                    "X-Role": auth["role"],
                },
                params={"q": q, "page": page, "per_page": 20},
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()
            results = data.get("items", [])
            total = data.get("total", 0)
            total_pages = data.get("total_pages", 0)
        except Exception as e:
            logger.error(f"Search failed: {e}")

    return templates.TemplateResponse(
        "search.html",
        {
            "request": request,
            "results": results,
            "query": q,
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "tenant_id": auth["tenant_id"],
            "user_id": auth["user_id"],
        },
    )


@app.get("/clusters", response_class=HTMLResponse)
async def clusters(
    request: Request,
    auth: dict = Depends(require_viewer),
    algorithm: str = Query(default=""),
):
    """Clusters list page."""
    import requests

    try:
        params = {}
        if algorithm:
            params["algorithm"] = algorithm

        response = requests.get(
            f"{config.INGEST_API_URL}/clusters",
            headers={
                "X-Tenant-Id": auth["tenant_id"],
                "X-User-Id": auth["user_id"],
                "X-Role": auth["role"],
            },
            params=params,
            timeout=10,
        )
        response.raise_for_status()
        clusters_list = response.json()
    except Exception as e:
        logger.error(f"Failed to fetch clusters: {e}")
        clusters_list = []

    return templates.TemplateResponse(
        "clusters.html",
        {
            "request": request,
            "clusters": clusters_list,
            "algorithm": algorithm,
            "tenant_id": auth["tenant_id"],
            "user_id": auth["user_id"],
        },
    )


@app.get("/cluster/{cluster_id}", response_class=HTMLResponse)
async def cluster_detail(
    cluster_id: str,
    request: Request,
    auth: dict = Depends(require_viewer),
):
    """Cluster detail page."""
    import requests

    try:
        response = requests.get(
            f"{config.INGEST_API_URL}/clusters/{cluster_id}",
            headers={
                "X-Tenant-Id": auth["tenant_id"],
                "X-User-Id": auth["user_id"],
                "X-Role": auth["role"],
            },
            timeout=10,
        )
        response.raise_for_status()
        cluster = response.json()
    except Exception as e:
        logger.error(f"Failed to fetch cluster: {e}")
        raise HTTPException(status_code=404, detail="Cluster not found")

    return templates.TemplateResponse(
        "cluster.html",
        {
            "request": request,
            "cluster": cluster,
            "tenant_id": auth["tenant_id"],
            "user_id": auth["user_id"],
        },
    )

