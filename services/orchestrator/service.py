"""Orchestrator service business logic."""

import logging
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.orchestrator.models import AuditAction, AuditLog, Job, JobStatus, Sample
from services.orchestrator.queue import get_redis_client

logger = logging.getLogger(__name__)


def get_job_by_id(db: Session, job_id: str) -> Job | None:
    """
    Get job by ID.

    Args:
        db: Database session
        job_id: Job UUID

    Returns:
        Job or None if not found
    """
    return db.get(Job, job_id)


def get_running_job_for_dispatch(
    db: Session,
    tenant_id: str,
    sample_sha256: str,
    pipeline_hash: str,
) -> Job | None:
    """
    Check if there's already a RUNNING job for the same dispatch tuple.

    Args:
        db: Database session
        tenant_id: Tenant identifier
        sample_sha256: Sample SHA256 hash
        pipeline_hash: Pipeline configuration hash

    Returns:
        Running job if exists, None otherwise
    """
    # Join with sample to get tenant_id and sha256
    return db.execute(
        select(Job)
        .join(Sample)
        .where(
            Sample.tenant_id == tenant_id,
            Sample.sha256 == sample_sha256,
            Job.pipeline_hash == pipeline_hash,
            Job.status == JobStatus.RUNNING,
        )
    ).scalar_one_or_none()


def mark_job_running(db: Session, job: Job) -> None:
    """
    Mark job as RUNNING and set started_at timestamp.

    Args:
        db: Database session
        job: Job to update
    """
    job.status = JobStatus.RUNNING
    job.started_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(job)


def mark_job_succeeded(
    db: Session,
    job: Job,
    result: str,
) -> None:
    """
    Mark job as SUCCEEDED and set completed_at timestamp.

    Args:
        db: Database session
        job: Job to update
        result: Job result data (JSON string)
    """
    job.status = JobStatus.SUCCEEDED
    job.completed_at = datetime.now(timezone.utc)
    job.result = result
    db.commit()
    db.refresh(job)


def mark_job_failed(
    db: Session,
    job: Job,
    error_message: str,
) -> None:
    """
    Mark job as FAILED and set completed_at timestamp.

    Args:
        db: Database session
        job: Job to update
        error_message: Error description
    """
    job.status = JobStatus.FAILED
    job.completed_at = datetime.now(timezone.utc)
    job.error_message = error_message
    db.commit()
    db.refresh(job)


def retry_job(db: Session, job: Job) -> Job:
    """
    Retry a failed job by creating a new job record.

    Args:
        db: Database session
        job: Failed job to retry

    Returns:
        New job record
    """
    new_job = Job(
        sample_id=job.sample_id,
        pipeline_name=job.pipeline_name,
        pipeline_hash=job.pipeline_hash,
        status=JobStatus.QUEUED,
        priority=job.priority,
        timeout_seconds=job.timeout_seconds,
    )
    db.add(new_job)
    db.commit()
    db.refresh(new_job)

    # Log audit
    audit_log = AuditLog(
        tenant_id=job.sample.tenant_id,
        action=AuditAction.JOB_RETRY,
        resource_type="job",
        resource_id=str(new_job.id),
        details={
            "original_job_id": str(job.id),
            "original_error": job.error_message,
        },
    )
    db.add(audit_log)
    db.commit()

    # Enqueue the new job
    redis_client = get_redis_client()
    redis_client.enqueue_job(str(new_job.id))

    return new_job


def create_audit_log(
    db: Session,
    tenant_id: str,
    action: AuditAction,
    resource_type: str,
    resource_id: str | None,
    details: dict | None = None,
) -> AuditLog:
    """
    Create an audit log entry.

    Args:
        db: Database session
        tenant_id: Tenant identifier
        action: Audit action
        resource_type: Type of resource
        resource_id: Resource identifier
        details: Additional details

    Returns:
        Created audit log
    """
    audit_log = AuditLog(
        tenant_id=tenant_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
    )
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)
    return audit_log


def dispatch_job_to_worker(db: Session, job: Job) -> bool:
    """
    Dispatch a job to the worker queue.

    Args:
        db: Database session
        job: Job to dispatch

    Returns:
        True if dispatched successfully
    """
    redis_client = get_redis_client()

    # Add to worker dispatch queue
    redis_client.enqueue_job(
        str(job.id),
        queue_name=redis_client.worker_dispatch_queue,
    )

    logger.info(
        "Job dispatched to worker",
        extra={
            "job_id": job.id,
            "sample_id": job.sample_id,
            "pipeline": job.pipeline_name,
        },
    )

    # Create audit log
    create_audit_log(
        db=db,
        tenant_id=job.sample.tenant_id,
        action=AuditAction.JOB_STARTED,
        resource_type="job",
        resource_id=str(job.id),
        details={
            "pipeline": job.pipeline_name,
            "worker_queue": redis_client.worker_dispatch_queue,
        },
    )

    return True


def consume_and_dispatch(db: Session) -> int:
    """
    Consume jobs from the ingest queue and dispatch to workers.

    This is the main dispatch loop - called periodically by a background task.

    Args:
        db: Database session

    Returns:
        Number of jobs dispatched
    """
    redis_client = get_redis_client()
    dispatched = 0

    # Get next job from ingest queue
    job_id = redis_client.dequeue_job(
        queue_name=redis_client.job_queue_name,
        timeout=0,  # Non-blocking
    )

    if not job_id:
        return 0

    # Get job from database
    job = get_job_by_id(db, job_id)

    if not job:
        logger.warning(f"Job not found: {job_id}")
        return 0

    # Check for concurrent execution (idempotency)
    existing_running = get_running_job_for_dispatch(
        db=db,
        tenant_id=job.sample.tenant_id,
        sample_sha256=job.sample.sha256,
        pipeline_hash=job.pipeline_hash,
    )

    if existing_running:
        logger.info(
            "Skipping dispatch - job already running for same tuple",
            extra={
                "job_id": job.id,
                "existing_running_id": existing_running.id,
            },
        )
        # Re-queue the job for later processing
        redis_client.enqueue_job(job_id, queue_name=redis_client.job_queue_name)
        return 0

    # Mark as running
    mark_job_running(db, job)

    # Dispatch to worker
    dispatch_job_to_worker(db, job)
    dispatched += 1

    return dispatched
