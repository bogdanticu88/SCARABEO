"""Worker job processor with analyzer routing and merging."""

import hashlib
import json
import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.worker.config import settings
from services.worker.database import get_session
from services.worker.docker_executor import DockerExecutor, DockerExecutionError
from services.worker.models import AuditAction, AuditLog, Job, JobStatus, Sample, SampleRelation, SampleRelationType
from services.worker.merger import merge_partial_outputs
from services.worker.router import get_analyzers_for_file_type, get_analyzer_container, get_analyzer_version
from services.worker.storage import get_storage_client, S3StorageError

logger = logging.getLogger(__name__)


def register_iocs(db: Session, report: dict) -> None:
    """
    Register IOCs from report for intelligence correlation.

    Args:
        db: Database session
        report: Analysis report dictionary
    """
    from services.search.models import IOCSighting
    from datetime import datetime, timezone

    iocs = report.get("iocs", [])
    sample_sha256 = report.get("sample_sha256")
    tenant_id = report.get("tenant_id")

    if not iocs:
        return

    now = datetime.now(timezone.utc)

    for ioc in iocs:
        try:
            ioc_value = ioc.get("value", "")
            ioc_type = ioc.get("type", "unknown")

            if not ioc_value:
                continue

            # Check if sighting exists
            existing = db.execute(
                select(IOCSighting).where(
                    IOCSighting.ioc_value == ioc_value,
                    IOCSighting.sample_sha256 == sample_sha256,
                    IOCSighting.tenant_id == tenant_id,
                )
            ).scalar_one_or_none()

            if existing:
                # Update last_seen
                existing.last_seen = now
            else:
                # Create new sighting
                sighting = IOCSighting(
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    sample_sha256=sample_sha256,
                    tenant_id=tenant_id,
                    first_seen=now,
                    last_seen=now,
                    sighting_count=1,
                    metadata=ioc,
                )
                db.add(sighting)

        except Exception as e:
            logger.error(f"Failed to register IOC: {e}")

    db.commit()
    logger.info(f"Registered {len(iocs)} IOCs for sample: {sample_sha256[:16]}...")


def process_clustering(db: Session, tenant_id: str, sample_sha256: str) -> None:
    """
    Process sample for similarity clustering.

    Args:
        db: Database session
        tenant_id: Tenant identifier
        sample_sha256: Sample SHA256
    """
    from services.worker.clustering import get_clustering_service

    def session_factory():
        return db

    clustering = get_clustering_service(session_factory)

    try:
        clusters = clustering.process_sample_for_clustering(tenant_id, sample_sha256)
        if clusters:
            logger.info(
                f"Sample {sample_sha256[:16]}... added to {len(clusters)} clusters",
                extra={"tenant_id": tenant_id},
            )
    except Exception as e:
        logger.error(f"Clustering failed for {sample_sha256[:16]}...: {e}")


TRIAGE_PIPELINE_PATH = Path(__file__).parent.parent.parent / "pipelines" / "triage.yaml"


def compute_pipeline_hash(pipeline_path: Path) -> str:
    """Compute SHA256 hash of pipeline file."""
    if not pipeline_path.exists():
        return hashlib.sha256(b"").hexdigest()
    with open(pipeline_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def build_analyzer_input(
    sample: Sample,
    pipeline_name: str,
    pipeline_hash: str,
) -> dict:
    """Build analyzer input.json."""
    return {
        "schema_version": "1.0.0",
        "sample_sha256": sample.sha256,
        "tenant_id": sample.tenant_id,
        "sample": {
            "filename": sample.filename,
            "size_bytes": sample.size_bytes,
            "storage_path": sample.storage_path,
        },
        "options": {
            "timeout_seconds": 300,
            "engines": [],
            "priority": "normal",
        },
        "metadata": {
            "pipeline_name": pipeline_name,
            "pipeline_hash": pipeline_hash,
            "file_type": sample.file_type,
        },
    }


def run_analyzer(
    executor: DockerExecutor,
    analyzer_name: str,
    work_dir: Path,
    sample_path: Path,
    input_data: dict,
    timeout: int,
) -> dict | None:
    """
    Run a single analyzer and return partial output.

    Returns None if analyzer produced no output.
    """
    container_image = get_analyzer_container(analyzer_name)
    if not container_image:
        logger.warning(f"Unknown analyzer: {analyzer_name}")
        return None

    # Ensure image is available
    if not executor.image_exists(container_image):
        logger.info(f"Pulling image: {container_image}")
        executor.pull_image(container_image)

    try:
        report_data, container_info = executor.run_analyzer(
            image=container_image,
            work_dir=work_dir,
            sample_path=sample_path,
            input_data=input_data,
            timeout=timeout,
        )

        # Check if it's a partial output or full report
        if "analyzer_name" in report_data:
            # Partial output
            return report_data
        elif "findings" in report_data and "sample_sha256" in report_data:
            # Full report from triage-universal - convert to partial
            return {
                "schema_version": report_data.get("schema_version", "1.0.0"),
                "analyzer_name": analyzer_name,
                "analyzer_version": get_analyzer_version(analyzer_name),
                "findings": report_data.get("findings", []),
                "iocs": report_data.get("iocs", []),
                "artifacts": report_data.get("artifacts", []),
                "metadata": report_data,
            }

    except DockerExecutionError as e:
        logger.error(f"Analyzer {analyzer_name} failed: {e}")

    return None


def store_report_and_artifacts(
    db: Session,
    job: Job,
    report_data: dict,
    work_dir: Path,
) -> None:
    """Store report and artifacts to S3."""
    storage_client = get_storage_client()
    storage_client.ensure_bucket_exists()

    tenant_id = job.sample.tenant_id
    sha256 = job.sample.sha256
    pipeline_hash = job.pipeline_hash

    # Store main report
    report_path = storage_client.get_report_path(tenant_id, sha256, pipeline_hash)
    storage_client.upload_json(report_data, report_path)
    logger.info(f"Report stored: {report_path}")

    # Store artifacts from all analyzer output directories
    for artifacts_dir in work_dir.glob("**/output/artifacts"):
        if artifacts_dir.is_dir():
            for artifact_file in artifacts_dir.glob("*"):
                if artifact_file.is_file():
                    artifact_path = storage_client.get_artifact_path(
                        tenant_id, sha256, pipeline_hash, artifact_file.name
                    )
                    storage_client.upload_file(artifact_file, artifact_path)
                    logger.info(f"Artifact stored: {artifact_path}")


def create_audit_log(
    db: Session,
    tenant_id: str,
    action: AuditAction,
    resource_type: str,
    resource_id: str,
    details: dict | None = None,
) -> None:
    """Create audit log entry."""
    audit_log = AuditLog(
        tenant_id=tenant_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
    )
    db.add(audit_log)
    db.commit()


def create_sample_relation(
    db: Session,
    parent_sha256: str,
    child_sha256: str,
    relationship: SampleRelationType,
    metadata: dict | None = None,
) -> SampleRelation:
    """Create sample relationship record."""
    relation = SampleRelation(
        parent_sha256=parent_sha256,
        child_sha256=child_sha256,
        relationship=relationship,
        metadata=metadata,
    )
    db.add(relation)
    db.commit()
    db.refresh(relation)
    return relation


def process_job(job_id: str) -> bool:
    """
    Process a single job with analyzer routing and merging.

    Args:
        job_id: Job UUID to process

    Returns:
        True if successful, False otherwise
    """
    db = get_session()

    try:
        job = db.get(Job, job_id)
        if not job:
            logger.error(f"Job not found: {job_id}")
            return False

        sample = job.sample
        logger.info(f"Processing job {job_id} for sample {sample.sha256}")

        # Get analyzers for this file type and pipeline
        feature_flags = {
            "YARA_ENABLED": settings.__dict__.get("YARA_ENABLED", False),
            "CAPA_ENABLED": settings.__dict__.get("CAPA_ENABLED", False),
        }

        analyzers = get_analyzers_for_file_type(
            file_type=sample.file_type,
            pipeline_name=job.pipeline_name,
            feature_flags=feature_flags,
        )

        logger.info(f"Running analyzers: {[a['name'] for a in analyzers]}")

        # Create working directory
        with tempfile.TemporaryDirectory() as tmpdir:
            work_dir = Path(tmpdir) / "work"
            work_dir.mkdir()
            output_dir = work_dir / "output"
            output_dir.mkdir()
            (output_dir / "artifacts").mkdir()

            # Download sample from storage
            storage_client = get_storage_client()
            sample_path = work_dir / "sample"
            logger.info(f"Downloading sample {sample.sha256} to {sample_path}")
            storage_client.download_file(sample.storage_path, sample_path)

            # Build input data
            input_data = build_analyzer_input(
                sample=sample,
                pipeline_name=job.pipeline_name,
                pipeline_hash=job.pipeline_hash,
            )
            input_data["metadata"]["analysis_start"] = datetime.now(timezone.utc).isoformat()

            # Run analyzers and collect partial outputs
            partials = []
            executor = DockerExecutor()

            for analyzer in analyzers:
                analyzer_name = analyzer["name"]
                logger.info(f"Running analyzer: {analyzer_name}")

                # Each analyzer gets its own work directory to avoid collision
                analyzer_work_dir = work_dir / analyzer_name
                analyzer_work_dir.mkdir()

                partial = run_analyzer(
                    executor=executor,
                    analyzer_name=analyzer_name,
                    work_dir=analyzer_work_dir,
                    sample_path=sample_path,
                    input_data=input_data,
                    timeout=job.timeout_seconds or 300,
                )

                if partial:
                    partials.append(partial)
                    logger.info(f"Analyzer {analyzer_name} completed")

            if not partials:
                raise DockerExecutionError("No analyzers produced output")

            # Merge partial outputs
            report_data = merge_partial_outputs(
                partials=partials,
                input_data=input_data,
                pipeline_name=job.pipeline_name,
                pipeline_hash=job.pipeline_hash,
            )

            # Store report and artifacts
            store_report_and_artifacts(
                db=db,
                job=job,
                report_data=report_data,
                work_dir=work_dir,
            )

            # Register IOCs for intelligence
            register_iocs(db, report_data)

            # Process sample for similarity clustering
            process_clustering(db, sample.tenant_id, sample.sha256)

            # Update job status
            job.status = JobStatus.SUCCEEDED
            job.completed_at = datetime.now(timezone.utc)
            job.result = json.dumps(report_data)
            db.commit()

            # Create audit log
            create_audit_log(
                db=db,
                tenant_id=sample.tenant_id,
                action=AuditAction.JOB_COMPLETED,
                resource_type="job",
                resource_id=job_id,
                details={
                    "pipeline": job.pipeline_name,
                    "analyzers_run": [a["name"] for a in analyzers],
                    "verdict": report_data.get("summary", {}).get("verdict", "unknown"),
                    "score": report_data.get("summary", {}).get("score", 0),
                },
            )

            logger.info(f"Job {job_id} completed successfully")
            return True

    except DockerExecutionError as e:
        logger.error(f"Job {job_id} failed: {e}")
        if job:
            job.status = JobStatus.FAILED
            job.completed_at = datetime.now(timezone.utc)
            job.error_message = str(e)
            db.commit()

            create_audit_log(
                db=db,
                tenant_id=job.sample.tenant_id,
                action=AuditAction.JOB_FAILED,
                resource_type="job",
                resource_id=job_id,
                details={"error": str(e)},
            )
        return False

    except S3StorageError as e:
        logger.error(f"Storage error for job {job_id}: {e}")
        if job:
            job.status = JobStatus.FAILED
            job.completed_at = datetime.now(timezone.utc)
            job.error_message = f"Storage error: {e}"
            db.commit()
        return False

    except Exception as e:
        logger.exception(f"Unexpected error processing job {job_id}: {e}")
        if job:
            job.status = JobStatus.FAILED
            job.completed_at = datetime.now(timezone.utc)
            job.error_message = f"Unexpected error: {e}"
            db.commit()
        return False

    finally:
        db.close()
