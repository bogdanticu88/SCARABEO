"""Review workflow API endpoints - verdict, tags, notes, findings."""

import logging
from datetime import datetime, timezone
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from scarabeo.auth import (
    AuthContext,
    Role,
    authenticate_from_headers,
    require_role,
    AuthError,
    ForbiddenError,
)
from scarabeo.metrics import get_metrics_collector


def get_session():
    """Lazy wrapper - defers import to avoid circular imports; allows test patching."""
    from services.ingest.database import get_session as _gs
    return _gs()

logger = logging.getLogger(__name__)

router = APIRouter(tags=["review"])


# Request/Response models
class VerdictRequest(BaseModel):
    """Verdict update request."""
    verdict: str  # unknown, benign, suspicious, malicious
    reason: str | None = None


class VerdictResponse(BaseModel):
    """Verdict response."""
    verdict: str
    reason: str | None
    set_by: str | None
    set_at: str


class TagRequest(BaseModel):
    """Tag add request."""
    tag: str


class TagsResponse(BaseModel):
    """Tags response."""
    tags: list[str]


class NoteRequest(BaseModel):
    """Note creation request."""
    body: str


class NoteResponse(BaseModel):
    """Note response."""
    id: str
    sample_sha256: str
    author_id: str
    author_role: str
    body: str
    created_at: str


class FindingStatusRequest(BaseModel):
    """Finding status update request."""
    status: str  # open, accepted, false_positive, resolved
    analyst_note: str | None = None


class FindingStatusResponse(BaseModel):
    """Finding status response."""
    finding_id: str
    status: str
    analyst_note: str | None
    last_updated_by: str | None
    last_updated_at: str


class ExportMetadata(BaseModel):
    """Export metadata."""
    sample_sha256: str
    tenant_id: str
    file_type: str
    verdict: str | None
    verdict_reason: str | None
    tags: list[str]
    notes_count: int
    exported_at: str
    exported_by: str


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


def get_db() -> Session:
    """Get database session."""
    return get_session()


@router.post("/samples/{sha256}/verdict", response_model=VerdictResponse)
def set_sample_verdict(
    sha256: str,
    verdict_data: VerdictRequest,
    auth: AuthContext = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """
    Set verdict for a sample. Requires analyst role.
    """
    from services.ingest.models import Sample, AuditAction, AuditLog

    # Get sample
    sample = db.execute(
        select(Sample).where(
            Sample.sha256 == sha256,
            Sample.tenant_id == auth.tenant_id,
        )
    ).scalar_one_or_none()

    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    # Validate verdict
    valid_verdicts = ["unknown", "benign", "suspicious", "malicious"]
    if verdict_data.verdict not in valid_verdicts:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid verdict. Must be one of: {valid_verdicts}",
        )

    # Update sample
    now = datetime.now(timezone.utc)
    stmt = (
        update(Sample)
        .where(Sample.id == sample.id)
        .values(
            verdict=verdict_data.verdict,
            verdict_reason=verdict_data.reason,
            verdict_set_by=auth.user_id,
            verdict_set_at=now,
        )
    )
    db.execute(stmt)
    db.commit()

    # Record metric
    metrics = get_metrics_collector()
    metrics.record_verdict(verdict_data.verdict, "ingest")

    # Audit log
    audit_log = AuditLog(
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        role=auth.role.value,
        action=AuditAction.JOB_UPDATED,
        target_type="sample",
        target_id=sample.id,
        status="success",
        ip_address=auth.ip_address,
        details_json={
            "action": "verdict_set",
            "verdict": verdict_data.verdict,
            "reason": verdict_data.reason,
        },
    )
    db.add(audit_log)
    db.commit()

    logger.info(
        f"Verdict set for sample {sha256[:16]}...: {verdict_data.verdict}",
        extra={"tenant_id": auth.tenant_id, "user_id": auth.user_id},
    )

    return VerdictResponse(
        verdict=verdict_data.verdict,
        reason=verdict_data.reason,
        set_by=auth.user_id,
        set_at=now.isoformat(),
    )


@router.post("/samples/{sha256}/tags", response_model=TagsResponse)
def add_sample_tag(
    sha256: str,
    tag_data: TagRequest,
    auth: AuthContext = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """
    Add a tag to a sample. Requires analyst role.
    """
    from services.ingest.models import Sample

    # Get sample
    sample = db.execute(
        select(Sample).where(
            Sample.sha256 == sha256,
            Sample.tenant_id == auth.tenant_id,
        )
    ).scalar_one_or_none()

    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    # Validate tag
    if not tag_data.tag or len(tag_data.tag) > 64:
        raise HTTPException(status_code=400, detail="Invalid tag")

    # Add tag if not exists
    current_tags = sample.tags or []
    if tag_data.tag not in current_tags:
        current_tags.append(tag_data.tag)
        stmt = (
            update(Sample)
            .where(Sample.id == sample.id)
            .values(tags=current_tags)
        )
        db.execute(stmt)
        db.commit()

    return TagsResponse(tags=current_tags)


@router.get("/samples/{sha256}/tags", response_model=TagsResponse)
def get_sample_tags(
    sha256: str,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
):
    """
    Get tags for a sample. Requires viewer role.
    """
    from services.ingest.models import Sample

    sample = db.execute(
        select(Sample).where(
            Sample.sha256 == sha256,
            Sample.tenant_id == auth.tenant_id,
        )
    ).scalar_one_or_none()

    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    return TagsResponse(tags=sample.tags or [])


@router.post("/samples/{sha256}/notes", response_model=NoteResponse)
def add_sample_note(
    sha256: str,
    note_data: NoteRequest,
    auth: AuthContext = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """
    Add a note to a sample. Requires analyst role.
    """
    from services.ingest.models import Sample, SampleNote

    # Get sample
    sample = db.execute(
        select(Sample).where(
            Sample.sha256 == sha256,
            Sample.tenant_id == auth.tenant_id,
        )
    ).scalar_one_or_none()

    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    # Validate note body
    if not note_data.body or len(note_data.body) > 10000:
        raise HTTPException(status_code=400, detail="Invalid note body")

    # Create note
    import uuid as _uuid
    note = SampleNote(
        id=str(_uuid.uuid4()),
        tenant_id=auth.tenant_id,
        sample_sha256=sha256,
        author_id=auth.user_id or "unknown",
        author_role=auth.role.value,
        body=note_data.body,
        created_at=datetime.now(timezone.utc),
    )
    db.add(note)

    # Update notes count
    stmt = (
        update(Sample)
        .where(Sample.id == sample.id)
        .values(notes_count=Sample.notes_count + 1)
    )
    db.execute(stmt)
    db.commit()
    db.refresh(note)

    # Record metric
    metrics = get_metrics_collector()
    metrics.record_note("ingest")

    return NoteResponse(
        id=note.id,
        sample_sha256=note.sample_sha256,
        author_id=note.author_id,
        author_role=note.author_role,
        body=note.body,
        created_at=note.created_at.isoformat(),
    )


@router.get("/samples/{sha256}/notes", response_model=list[NoteResponse])
def get_sample_notes(
    sha256: str,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
):
    """
    Get notes for a sample. Requires viewer role.
    """
    from services.ingest.models import SampleNote

    # Verify sample exists
    sample = db.execute(
        select(Sample).where(
            Sample.sha256 == sha256,
            Sample.tenant_id == auth.tenant_id,
        )
    ).scalar_one_or_none()

    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    # Get notes
    stmt = (
        select(SampleNote)
        .where(
            SampleNote.sample_sha256 == sha256,
            SampleNote.tenant_id == auth.tenant_id,
        )
        .order_by(SampleNote.created_at.desc())
    )
    notes = db.execute(stmt).scalars().all()

    return [
        NoteResponse(
            id=note.id,
            sample_sha256=note.sample_sha256,
            author_id=note.author_id,
            author_role=note.author_role,
            body=note.body,
            created_at=note.created_at.isoformat(),
        )
        for note in notes
    ]


@router.post("/samples/{sha256}/findings/{finding_id}/status", response_model=FindingStatusResponse)
def set_finding_status(
    sha256: str,
    finding_id: str,
    status_data: FindingStatusRequest,
    auth: AuthContext = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """
    Set status for a finding. Requires analyst role.
    """
    from services.ingest.models import FindingStatus as FindingStatusEnum, FindingStatusRecord, Sample

    # Verify sample exists
    sample = db.execute(
        select(Sample).where(
            Sample.sha256 == sha256,
            Sample.tenant_id == auth.tenant_id,
        )
    ).scalar_one_or_none()

    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    # Validate status
    try:
        status = FindingStatusEnum(status_data.status)
    except ValueError:
        valid_statuses = [s.value for s in FindingStatusEnum]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {valid_statuses}",
        )

    # Get or create finding status record
    record = db.execute(
        select(FindingStatusRecord).where(
            FindingStatusRecord.sample_sha256 == sha256,
            FindingStatusRecord.finding_id == finding_id,
        )
    ).scalar_one_or_none()

    now = datetime.now(timezone.utc)

    if record:
        # Update existing
        stmt = (
            update(FindingStatusRecord)
            .where(FindingStatusRecord.id == record.id)
            .values(
                status=status,
                analyst_note=status_data.analyst_note,
                last_updated_by=auth.user_id,
                last_updated_at=now,
            )
        )
        db.execute(stmt)
    else:
        # Create new
        record = FindingStatusRecord(
            tenant_id=auth.tenant_id,
            sample_sha256=sha256,
            finding_id=finding_id,
            status=status,
            analyst_note=status_data.analyst_note,
            last_updated_by=auth.user_id,
        )
        db.add(record)

    db.commit()
    if record:
        db.refresh(record)

    return FindingStatusResponse(
        finding_id=finding_id,
        status=status.value,
        analyst_note=status_data.analyst_note,
        last_updated_by=auth.user_id,
        last_updated_at=now.isoformat(),
    )


@router.get("/samples/{sha256}/export")
def export_sample(
    sha256: str,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
):
    """
    Export sample data as deterministic ZIP.
    Contains: report.json, artifacts, notes.json, metadata.json
    """
    import json
    from services.ingest.models import Sample, SampleNote, Job
    from services.ingest.storage import get_storage_client, S3StorageError

    # Get sample
    sample = db.execute(
        select(Sample).where(
            Sample.sha256 == sha256,
            Sample.tenant_id == auth.tenant_id,
        )
    ).scalar_one_or_none()

    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    # Get latest job for report
    job = db.execute(
        select(Job)
        .where(Job.sample_id == sample.id)
        .order_by(Job.created_at.desc())
    ).scalar_one_or_none()

    if not job or not job.result:
        raise HTTPException(status_code=404, detail="No report available")

    # Get notes
    notes_stmt = (
        select(SampleNote)
        .where(
            SampleNote.sample_sha256 == sha256,
            SampleNote.tenant_id == auth.tenant_id,
        )
        .order_by(SampleNote.created_at)
    )
    notes = db.execute(notes_stmt).scalars().all()

    # Create deterministic ZIP
    zip_buffer = BytesIO()
    fixed_timestamp = (2024, 1, 1, 0, 0, 0)  # Fixed timestamp for determinism

    with ZipFile(zip_buffer, "w", ZIP_DEFLATED, compresslevel=6) as zf:
        # Add report.json
        report_info = ZipInfo("report.json", date_time=fixed_timestamp)
        report_info.compress_type = ZIP_DEFLATED
        zf.writestr(report_info, job.result)

        # Add notes.json
        notes_data = [
            {
                "id": note.id,
                "author_id": note.author_id,
                "author_role": note.author_role,
                "body": note.body,
                "created_at": note.created_at.isoformat(),
            }
            for note in notes
        ]
        notes_json = json.dumps(notes_data, indent=2, sort_keys=True)
        notes_info = ZipInfo("notes.json", date_time=fixed_timestamp)
        notes_info.compress_type = ZIP_DEFLATED
        zf.writestr(notes_info, notes_json)

        # Add metadata.json
        metadata = ExportMetadata(
            sample_sha256=sample.sha256,
            tenant_id=sample.tenant_id,
            file_type=sample.file_type,
            verdict=sample.verdict,
            verdict_reason=sample.verdict_reason,
            tags=sample.tags or [],
            notes_count=sample.notes_count or 0,
            exported_at=datetime.now(timezone.utc).isoformat(),
            exported_by=auth.user_id or "unknown",
        )
        metadata_json = json.dumps(metadata.model_dump(), indent=2, sort_keys=True)
        metadata_info = ZipInfo("metadata.json", date_time=fixed_timestamp)
        metadata_info.compress_type = ZIP_DEFLATED
        zf.writestr(metadata_info, metadata_json)

        # Try to add artifacts from S3
        try:
            storage = get_storage_client()
            pipeline_hash = job.pipeline_hash
            artifact_prefix = f"samples/{auth.tenant_id}/{sha256}/artifacts/{pipeline_hash}/"

            # List artifacts (simplified - in production would use S3 list)
            # For now, just note that artifacts would be included
            artifacts_manifest = json.dumps({
                "prefix": artifact_prefix,
                "note": "Artifacts would be included here in production",
            }, indent=2, sort_keys=True)
            artifacts_info = ZipInfo("artifacts/manifest.json", date_time=fixed_timestamp)
            artifacts_info.compress_type = ZIP_DEFLATED
            zf.writestr(artifacts_info, artifacts_manifest)

        except S3StorageError:
            pass  # Artifacts optional

    zip_buffer.seek(0)

    # Record metric
    metrics = get_metrics_collector()
    metrics.record_export("ingest")

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={sha256[:16]}_export.zip"},
    )
