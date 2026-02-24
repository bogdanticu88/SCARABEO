"""Case management API endpoints."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
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

router = APIRouter(prefix="/cases", tags=["cases"])


# Request/Response models
class CaseCreate(BaseModel):
    """Case creation request."""
    name: str
    description: str | None = None


class CaseResponse(BaseModel):
    """Case response."""
    id: str
    tenant_id: str
    name: str
    description: str | None
    created_by: str | None
    created_at: str
    updated_at: str
    sample_count: int


class CaseDetailResponse(BaseModel):
    """Case detail response."""
    id: str
    tenant_id: str
    name: str
    description: str | None
    created_by: str | None
    created_at: str
    updated_at: str
    samples: list[dict]


class AddSampleRequest(BaseModel):
    """Add sample to case request."""
    sample_sha256: str
    notes: str | None = None


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


def require_analyst(auth: AuthContext = Depends(get_auth)) -> AuthContext:
    """Require analyst role."""
    try:
        require_role(auth, Role.ANALYST)
    except ForbiddenError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    return auth


@router.get("", response_model=list[CaseResponse])
def list_cases(
    auth: AuthContext = Depends(require_analyst),
    db: Session = Depends(lambda: None),  # Will be injected
):
    """List cases for tenant."""
    from services.search.models import Case, CaseSample
    from services.search.database import get_session

    db = get_session()
    try:
        stmt = (
            select(Case)
            .where(Case.tenant_id == auth.tenant_id)
            .order_by(Case.created_at.desc())
        )
        cases = db.execute(stmt).scalars().all()

        return [
            CaseResponse(
                id=c.id,
                tenant_id=c.tenant_id,
                name=c.name,
                description=c.description,
                created_by=c.created_by,
                created_at=c.created_at.isoformat(),
                updated_at=c.updated_at.isoformat(),
                sample_count=len(c.samples),
            )
            for c in cases
        ]
    finally:
        db.close()


@router.post("", response_model=CaseResponse)
def create_case(
    case_data: CaseCreate,
    auth: AuthContext = Depends(require_analyst),
    db: Session = Depends(lambda: None),
):
    """Create a new case."""
    from services.search.models import Case
    from services.search.database import get_session

    db = get_session()
    try:
        case = Case(
            tenant_id=auth.tenant_id,
            name=case_data.name,
            description=case_data.description,
            created_by=auth.user_id,
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        logger.info(
            f"Case created: {case.id}",
            extra={"tenant_id": auth.tenant_id, "user_id": auth.user_id},
        )

        return CaseResponse(
            id=case.id,
            tenant_id=case.tenant_id,
            name=case.name,
            description=case.description,
            created_by=case.created_by,
            created_at=case.created_at.isoformat(),
            updated_at=case.updated_at.isoformat(),
            sample_count=0,
        )
    finally:
        db.close()


@router.get("/{case_id}", response_model=CaseDetailResponse)
def get_case(
    case_id: str,
    auth: AuthContext = Depends(require_analyst),
    db: Session = Depends(lambda: None),
):
    """Get case details."""
    from services.search.models import Case
    from services.search.database import get_session

    db = get_session()
    try:
        case = db.get(Case, case_id)

        if not case or case.tenant_id != auth.tenant_id:
            raise HTTPException(status_code=404, detail="Case not found")

        return CaseDetailResponse(
            id=case.id,
            tenant_id=case.tenant_id,
            name=case.name,
            description=case.description,
            created_by=case.created_by,
            created_at=case.created_at.isoformat(),
            updated_at=case.updated_at.isoformat(),
            samples=[
                {
                    "sample_sha256": cs.sample_sha256,
                    "added_at": cs.added_at.isoformat(),
                    "notes": cs.notes,
                }
                for cs in case.samples
            ],
        )
    finally:
        db.close()


@router.post("/{case_id}/samples")
def add_sample_to_case(
    case_id: str,
    sample_data: AddSampleRequest,
    auth: AuthContext = Depends(require_analyst),
    db: Session = Depends(lambda: None),
):
    """Add sample to case."""
    from services.search.models import Case, CaseSample
    from services.search.database import get_session

    db = get_session()
    try:
        case = db.get(Case, case_id)

        if not case or case.tenant_id != auth.tenant_id:
            raise HTTPException(status_code=404, detail="Case not found")

        # Check if sample already in case
        existing = db.execute(
            select(CaseSample).where(
                CaseSample.case_id == case_id,
                CaseSample.sample_sha256 == sample_data.sample_sha256,
            )
        ).scalar_one_or_none()

        if existing:
            raise HTTPException(status_code=400, detail="Sample already in case")

        case_sample = CaseSample(
            case_id=case_id,
            sample_sha256=sample_data.sample_sha256,
            notes=sample_data.notes,
        )
        db.add(case_sample)
        db.commit()

        logger.info(
            f"Sample added to case: {case_id}",
            extra={
                "tenant_id": auth.tenant_id,
                "user_id": auth.user_id,
                "sample_sha256": sample_data.sample_sha256,
            },
        )

        return {"status": "ok", "message": "Sample added to case"}
    finally:
        db.close()


@router.get("/{case_id}/samples")
def get_case_samples(
    case_id: str,
    auth: AuthContext = Depends(require_analyst),
    db: Session = Depends(lambda: None),
):
    """Get samples in case."""
    from services.search.models import CaseSample
    from services.search.database import get_session

    db = get_session()
    try:
        case = db.get(Case, case_id)

        if not case or case.tenant_id != auth.tenant_id:
            raise HTTPException(status_code=404, detail="Case not found")

        return {
            "case_id": case_id,
            "samples": [
                {
                    "sample_sha256": cs.sample_sha256,
                    "added_at": cs.added_at.isoformat(),
                    "notes": cs.notes,
                }
                for cs in case.samples
            ],
            "total": len(case.samples),
        }
    finally:
        db.close()
