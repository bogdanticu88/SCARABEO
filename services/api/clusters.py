"""Cluster API endpoints for similarity clustering."""

import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from scarabeo.auth import (
    AuthContext,
    Role,
    authenticate_from_headers,
    require_role,
    AuthError,
    ForbiddenError,
)
logger = logging.getLogger(__name__)


def get_session():
    """Lazy wrapper - defers import to avoid circular imports; allows test patching."""
    from services.ingest.database import get_session as _gs
    return _gs()

router = APIRouter(prefix="/clusters", tags=["clusters"])


# Request/Response models
class ClusterResponse(BaseModel):
    """Cluster response."""
    cluster_id: str
    tenant_id: str
    algorithm: str
    threshold: int
    primary_sample_sha256: str
    member_count: int
    created_at: str


class ClusterDetailResponse(BaseModel):
    """Cluster detail response."""
    cluster_id: str
    tenant_id: str
    algorithm: str
    threshold: int
    primary_sample_sha256: str
    created_at: str
    members: list[dict]


class ClusterMemberResponse(BaseModel):
    """Cluster member response."""
    sample_sha256: str
    score: int
    added_at: str


class SampleClustersResponse(BaseModel):
    """Sample clusters response."""
    sample_sha256: str
    clusters: list[dict]


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


def get_db() -> Session:
    """Get database session."""
    return get_session()


@router.get("", response_model=list[ClusterResponse])
def list_clusters(
    algorithm: str | None = Query(None, description="Filter by algorithm"),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    auth: AuthContext = Depends(require_viewer),
    db: Session = Depends(get_db),
):
    """
    List clusters for tenant.
    """
    from services.ingest.models import Cluster, ClusterMember
    from sqlalchemy import func

    # Build query
    stmt = (
        select(Cluster)
        .where(Cluster.tenant_id == auth.tenant_id)
        .order_by(Cluster.created_at.desc())
    )

    if algorithm:
        stmt = stmt.where(Cluster.algorithm == algorithm)

    # Apply pagination
    offset = (page - 1) * per_page
    stmt = stmt.offset(offset).limit(per_page)

    clusters = db.execute(stmt).scalars().all()

    # Get member counts
    results = []
    for cluster in clusters:
        count_stmt = (
            select(func.count())
            .select_from(ClusterMember)
            .where(ClusterMember.cluster_id == cluster.cluster_id)
        )
        member_count = db.execute(count_stmt).scalar()

        results.append(
            ClusterResponse(
                cluster_id=str(cluster.cluster_id),
                tenant_id=cluster.tenant_id,
                algorithm=cluster.algorithm,
                threshold=cluster.threshold,
                primary_sample_sha256=cluster.primary_sample_sha256,
                member_count=member_count,
                created_at=cluster.created_at.isoformat(),
            )
        )

    return results


@router.get("/{cluster_id}", response_model=ClusterDetailResponse)
def get_cluster(
    cluster_id: str,
    auth: AuthContext = Depends(require_viewer),
    db: Session = Depends(get_db),
):
    """
    Get cluster details with members.
    """
    from services.ingest.models import Cluster, ClusterMember

    try:
        cluster_uuid = UUID(cluster_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid cluster ID")

    cluster = db.execute(
        select(Cluster).where(
            Cluster.cluster_id == cluster_uuid,
            Cluster.tenant_id == auth.tenant_id,
        )
    ).scalar_one_or_none()

    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    # Get members
    members_stmt = (
        select(ClusterMember)
        .where(ClusterMember.cluster_id == cluster_uuid)
        .order_by(ClusterMember.added_at.desc())
    )
    members = db.execute(members_stmt).scalars().all()

    return ClusterDetailResponse(
        cluster_id=str(cluster.cluster_id),
        tenant_id=cluster.tenant_id,
        algorithm=cluster.algorithm,
        threshold=cluster.threshold,
        primary_sample_sha256=cluster.primary_sample_sha256,
        created_at=cluster.created_at.isoformat(),
        members=[
            {
                "sample_sha256": m.sample_sha256,
                "score": m.score,
                "added_at": m.added_at.isoformat(),
            }
            for m in members
        ],
    )


@router.get("/{cluster_id}/members", response_model=list[ClusterMemberResponse])
def get_cluster_members(
    cluster_id: str,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(require_viewer),
    db: Session = Depends(get_db),
):
    """
    Get cluster members.
    """
    from services.ingest.models import Cluster, ClusterMember

    try:
        cluster_uuid = UUID(cluster_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid cluster ID")

    # Verify cluster exists and belongs to tenant
    cluster = db.execute(
        select(Cluster).where(
            Cluster.cluster_id == cluster_uuid,
            Cluster.tenant_id == auth.tenant_id,
        )
    ).scalar_one_or_none()

    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    # Get members with pagination
    offset = (page - 1) * per_page
    members_stmt = (
        select(ClusterMember)
        .where(ClusterMember.cluster_id == cluster_uuid)
        .order_by(ClusterMember.added_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    members = db.execute(members_stmt).scalars().all()

    return [
        ClusterMemberResponse(
            sample_sha256=m.sample_sha256,
            score=m.score,
            added_at=m.added_at.isoformat(),
        )
        for m in members
    ]


@router.get("/samples/{sha256}/clusters", response_model=SampleClustersResponse)
def get_sample_clusters(
    sha256: str,
    auth: AuthContext = Depends(require_viewer),
    db: Session = Depends(get_db),
):
    """
    Get clusters containing a sample.
    """
    from services.ingest.models import Cluster, ClusterMember

    # Get all clusters containing this sample
    stmt = (
        select(Cluster, ClusterMember.score)
        .join(ClusterMember, Cluster.cluster_id == ClusterMember.cluster_id)
        .where(
            ClusterMember.sample_sha256 == sha256,
            Cluster.tenant_id == auth.tenant_id,
        )
        .order_by(Cluster.created_at.desc())
    )

    results = db.execute(stmt).all()

    if not results:
        return SampleClustersResponse(sample_sha256=sha256, clusters=[])

    return SampleClustersResponse(
        sample_sha256=sha256,
        clusters=[
            {
                "cluster_id": str(row.Cluster.cluster_id),
                "algorithm": row.Cluster.algorithm,
                "score": row.score,
                "created_at": row.Cluster.created_at.isoformat(),
            }
            for row in results
        ],
    )
