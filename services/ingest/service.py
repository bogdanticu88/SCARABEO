"""Ingest service business logic."""

import hashlib
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.ingest.models import AuditAction, AuditLog, Job, JobStatus, Sample
from services.ingest.queue import get_redis_client
from services.ingest.storage import get_storage_client
from services.ingest.filetype import detect_file_type, FileType

logger = logging.getLogger(__name__)


# Pipeline configuration path
TRIAGE_PIPELINE_PATH = Path(__file__).parent.parent.parent / "pipelines" / "triage.yaml"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal and special characters.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename safe for storage
    """
    # Remove path components (handle both Unix and Windows-style paths)
    filename = filename.replace("\\", "/")
    filename = Path(filename).name

    # Remove or replace dangerous characters
    # Keep alphanumeric, dots, hyphens, underscores
    sanitized = re.sub(r"[^\w.\-]", "_", filename)

    # Limit length
    if len(sanitized) > 255:
        name, ext = sanitized.rsplit(".", 1) if "." in sanitized else (sanitized, "")
        max_name_len = 255 - len(ext) - 1 if ext else 254
        sanitized = f"{name[:max_name_len]}.{ext}" if ext else name[:max_name_len]

    # Prevent hidden files
    if sanitized.startswith("."):
        sanitized = "_" + sanitized[1:]

    return sanitized or "unnamed_file"


def compute_pipeline_hash(pipeline_path: Path) -> str:
    """
    Compute SHA256 hash of pipeline configuration file.

    Args:
        pipeline_path: Path to pipeline YAML file

    Returns:
        SHA256 hex string of file contents
    """
    pipeline_path = Path(pipeline_path)
    if not pipeline_path.exists():
        # Return hash of empty string if pipeline doesn't exist yet
        return hashlib.sha256(b"").hexdigest()

    with open(pipeline_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def upload_sample(
    db: Session,
    file_obj: BinaryIO,
    filename: str,
    tenant_id: str,
    file_size: int,
    priority: str = "normal",
    timeout_seconds: int | None = None,
) -> tuple[Sample, Job]:
    """
    Upload sample and create analysis job.

    Args:
        db: Database session
        file_obj: File object opened in binary mode
        filename: Original filename
        tenant_id: Tenant identifier
        file_size: File size in bytes
        priority: Job priority
        timeout_seconds: Analysis timeout

    Returns:
        Tuple of (Sample, Job) - existing or newly created
    """
    # Sanitize filename
    safe_filename = sanitize_filename(filename)

    # Compute hashes while streaming
    from services.ingest.hashing import compute_hashes_streaming

    # Store file position to reset after hashing
    initial_pos = file_obj.tell()

    # Compute hashes
    file_obj.seek(0)
    hashes = compute_hashes_streaming(file_obj)
    sha256 = hashes.sha256

    # Reset file position for storage upload
    file_obj.seek(0)

    # Detect file type (read first 16 bytes for magic detection)
    file_obj.seek(0)
    header = file_obj.read(16)
    file_obj.seek(0)
    file_type = detect_file_type(header, safe_filename)

    # Get storage client and upload
    storage_client = get_storage_client()
    storage_path = storage_client.get_storage_path(tenant_id, sha256)

    # Upload to S3
    storage_client.upload_file(
        file_obj=file_obj,
        object_key=storage_path,
        content_type="application/octet-stream",
        metadata={
            "tenant_id": tenant_id,
            "sha256": sha256,
            "original_filename": safe_filename,
        },
    )

    logger.info(
        "Sample uploaded",
        extra={
            "tenant_id": tenant_id,
            "sha256": sha256,
            "storage_path": storage_path,
        },
    )

    # Check for existing sample (idempotency)
    existing_sample = db.execute(
        select(Sample).where(
            Sample.tenant_id == tenant_id,
            Sample.sha256 == sha256,
        )
    ).scalar_one_or_none()

    if existing_sample:
        # Sample exists - create new job but don't re-upload
        logger.info(
            "Sample already exists, creating new job",
            extra={"tenant_id": tenant_id, "sha256": sha256},
        )

        # Log audit
        audit_log = AuditLog(
            tenant_id=tenant_id,
            action=AuditAction.SAMPLE_UPLOAD,
            resource_type="sample",
            resource_id=existing_sample.id,
            details={
                "sha256": sha256,
                "filename": safe_filename,
                "duplicate": True,
            },
        )
        db.add(audit_log)
        db.commit()

        # Create new job for existing sample
        pipeline_hash = compute_pipeline_hash(TRIAGE_PIPELINE_PATH)
        job = Job(
            sample_id=existing_sample.id,
            pipeline_name="triage",
            pipeline_hash=pipeline_hash,
            status=JobStatus.QUEUED,
            priority=priority,
            timeout_seconds=timeout_seconds,
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        # Enqueue job
        redis_client = get_redis_client()
        redis_client.enqueue_job(str(job.id))

        # Log job creation audit
        job_audit = AuditLog(
            tenant_id=tenant_id,
            action=AuditAction.JOB_CREATED,
            resource_type="job",
            resource_id=str(job.id),
            details={
                "sample_id": str(existing_sample.id),
                "pipeline": "triage",
            },
        )
        db.add(job_audit)
        db.commit()

        return existing_sample, job

    # Create new sample record
    sample = Sample(
        sha256=hashes.sha256,
        sha1=hashes.sha1,
        md5=hashes.md5,
        tenant_id=tenant_id,
        filename=safe_filename,
        file_type=file_type.value,
        size_bytes=file_size,
        storage_path=storage_path,
    )
    db.add(sample)
    db.commit()
    db.refresh(sample)

    logger.info(
        "Sample record created",
        extra={
            "sample_id": sample.id,
            "tenant_id": tenant_id,
            "sha256": sha256,
        },
    )

    # Create job
    pipeline_hash = compute_pipeline_hash(TRIAGE_PIPELINE_PATH)
    job = Job(
        sample_id=sample.id,
        pipeline_name="triage",
        pipeline_hash=pipeline_hash,
        status=JobStatus.QUEUED,
        priority=priority,
        timeout_seconds=timeout_seconds,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Enqueue job
    redis_client = get_redis_client()
    redis_client.enqueue_job(str(job.id))

    logger.info(
        "Job created and enqueued",
        extra={
            "job_id": job.id,
            "sample_id": sample.id,
            "queue": redis_client.queue_name,
        },
    )

    # Log audit events
    sample_audit = AuditLog(
        tenant_id=tenant_id,
        action=AuditAction.SAMPLE_UPLOAD,
        resource_type="sample",
        resource_id=sample.id,
        details={
            "sha256": sha256,
            "filename": safe_filename,
            "file_type": file_type.value,
            "size_bytes": file_size,
        },
    )
    db.add(sample_audit)

    job_audit = AuditLog(
        tenant_id=tenant_id,
        action=AuditAction.JOB_CREATED,
        resource_type="job",
        resource_id=str(job.id),
        details={
            "sample_id": str(sample.id),
            "pipeline": "triage",
        },
    )
    db.add(job_audit)
    db.commit()

    return sample, job


def get_sample_by_sha256(
    db: Session,
    sha256: str,
    tenant_id: str,
) -> Sample | None:
    """
    Get sample by SHA256 hash for tenant.

    Args:
        db: Database session
        sha256: Sample SHA256 hash
        tenant_id: Tenant identifier

    Returns:
        Sample or None if not found
    """
    return db.execute(
        select(Sample).where(
            Sample.sha256 == sha256,
            Sample.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()


def list_samples(
    db: Session,
    tenant_id: str,
    page: int = 1,
    per_page: int = 20,
    status: str | None = None,
) -> tuple[list[Sample], int]:
    """
    List samples for tenant with pagination.

    Args:
        db: Database session
        tenant_id: Tenant identifier
        page: Page number (1-indexed)
        per_page: Items per page
        status: Optional status filter

    Returns:
        Tuple of (samples list, total count)
    """
    # Base query
    query = select(Sample).where(Sample.tenant_id == tenant_id)

    # Count total
    total_query = select(Sample.id).where(Sample.tenant_id == tenant_id)
    total = db.execute(total_query).scalars().count()

    # Order by created_at desc, sha256 for stable ordering
    query = query.order_by(Sample.created_at.desc(), Sample.sha256)

    # Apply pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    samples = db.execute(query).scalars().all()

    return list(samples), total


def get_sample_jobs(
    db: Session,
    sample_id: str,
) -> list[Job]:
    """
    Get all jobs for a sample.

    Args:
        db: Database session
        sample_id: Sample UUID

    Returns:
        List of jobs
    """
    return db.execute(
        select(Job).where(Job.sample_id == sample_id).order_by(Job.created_at.desc())
    ).scalars().all()


def get_latest_job_for_sample(
    db: Session,
    sample_id: str,
) -> Job | None:
    """
    Get the most recent job for a sample.

    Args:
        db: Database session
        sample_id: Sample UUID

    Returns:
        Latest job or None
    """
    return db.execute(
        select(Job)
        .where(Job.sample_id == sample_id)
        .order_by(Job.created_at.desc())
    ).scalar_one_or_none()
