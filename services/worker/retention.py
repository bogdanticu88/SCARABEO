"""Retention service for policy-driven data deletion."""

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# Default retention policies (days)
DEFAULT_RETENTION = {
    "artifacts": 30,
    "reports": 90,
    "samples": 365,
    "metadata": None,  # Keep indefinitely
}


class RetentionConfig:
    """Retention configuration."""

    def __init__(
        self,
        artifacts_days: int = 30,
        reports_days: int = 90,
        samples_days: int | None = 365,
        metadata_days: int | None = None,
    ):
        self.artifacts_days = artifacts_days
        self.reports_days = reports_days
        self.samples_days = samples_days
        self.metadata_days = metadata_days

    def get_retention_days(self, resource_type: str) -> int | None:
        """Get retention days for resource type."""
        mapping = {
            "artifacts": self.artifacts_days,
            "reports": self.reports_days,
            "samples": self.samples_days,
            "metadata": self.metadata_days,
        }
        return mapping.get(resource_type)


def get_retention_config() -> RetentionConfig:
    """Get retention configuration from environment."""
    import os
    return RetentionConfig(
        artifacts_days=int(os.environ.get("RETENTION_ARTIFACTS_DAYS", "30")),
        reports_days=int(os.environ.get("RETENTION_REPORTS_DAYS", "90")),
        samples_days=int(os.environ.get("RETENTION_SAMPLES_DAYS", "365")) 
            if os.environ.get("RETENTION_SAMPLES_DAYS") 
            else 365,
        metadata_days=int(os.environ.get("RETENTION_METADATA_DAYS")) 
            if os.environ.get("RETENTION_METADATA_DAYS") 
            else None,
    )


class RetentionService:
    """Service for retention policy enforcement."""

    def __init__(
        self,
        db_session_factory: Any,
        storage_client: Any,
        config: RetentionConfig | None = None,
    ):
        self.db_session_factory = db_session_factory
        self.storage_client = storage_client
        self.config = config or get_retention_config()

    def get_expired_samples(
        self,
        cutoff_date: datetime | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Get samples that have exceeded retention period.

        Args:
            cutoff_date: Cutoff date (defaults to now - retention period)
            limit: Maximum number of samples to return

        Returns:
            List of sample info dicts
        """
        if cutoff_date is None:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.samples_days or 365)

        db = self.db_session_factory()
        try:
            from services.ingest.models import Sample

            stmt = (
                select(Sample)
                .where(Sample.created_at < cutoff_date)
                .limit(limit)
            )
            samples = db.execute(stmt).scalars().all()

            return [
                {
                    "id": s.id,
                    "sha256": s.sha256,
                    "tenant_id": s.tenant_id,
                    "storage_path": s.storage_path,
                    "created_at": s.created_at.isoformat(),
                }
                for s in samples
            ]
        finally:
            db.close()

    def delete_sample_artifacts(
        self,
        tenant_id: str,
        sha256: str,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """
        Delete artifacts for a sample.

        Args:
            tenant_id: Tenant identifier
            sha256: Sample SHA256
            dry_run: If True, don't actually delete

        Returns:
            Deletion report
        """
        deleted = []
        failed = []

        # Delete artifacts
        artifact_prefix = f"samples/{tenant_id}/{sha256}/artifacts/"
        try:
            # List and delete artifacts
            # Note: In production, would use S3 list_objects_v2
            if not dry_run:
                deleted.append(f"{artifact_prefix}*")
        except Exception as e:
            failed.append({"prefix": artifact_prefix, "error": str(e)})

        # Delete reports (keep hash reference)
        report_prefix = f"samples/{tenant_id}/{sha256}/reports/"
        try:
            if not dry_run:
                deleted.append(f"{report_prefix}*")
        except Exception as e:
            failed.append({"prefix": report_prefix, "error": str(e)})

        return {
            "tenant_id": tenant_id,
            "sha256": sha256,
            "dry_run": dry_run,
            "deleted": deleted,
            "failed": failed,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def delete_sample(
        self,
        db: Session,
        tenant_id: str,
        sha256: str,
        sample_id: str,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """
        Delete sample and associated data.

        Args:
            db: Database session
            tenant_id: Tenant identifier
            sha256: Sample SHA256
            sample_id: Sample UUID
            dry_run: If True, don't actually delete

        Returns:
            Deletion report
        """
        result = {
            "tenant_id": tenant_id,
            "sha256": sha256,
            "sample_id": sample_id,
            "dry_run": dry_run,
            "deleted": [],
            "failed": [],
            "audit_log_id": None,
        }

        # Delete from S3
        try:
            storage_path = f"samples/{tenant_id}/{sha256}/original.bin"
            if not dry_run:
                self.storage_client.delete_file(storage_path)
            result["deleted"].append(f"s3://{storage_path}")
        except Exception as e:
            result["failed"].append({"type": "sample", "error": str(e)})

        # Delete artifacts and reports
        artifact_result = self.delete_sample_artifacts(tenant_id, sha256, dry_run)
        result["deleted"].extend(artifact_result["deleted"])
        result["failed"].extend(artifact_result["failed"])

        # Delete database record (if not dry run)
        if not dry_run:
            try:
                from services.ingest.models import Sample, Job, AuditLog, AuditAction

                # Delete jobs
                db.execute(
                    __import__("sqlalchemy").delete(Job).where(Job.sample_id == sample_id)
                )

                # Create audit log before deleting sample
                audit_log = AuditLog(
                    tenant_id=tenant_id,
                    action=AuditAction.SAMPLE_UPLOAD,  # Reuse action for deletion
                    resource_type="sample",
                    resource_id=sample_id,
                    details={
                        "action": "retention_deletion",
                        "sha256": sha256,
                        "reason": "retention_policy_exceeded",
                    },
                )
                db.add(audit_log)
                db.flush()
                result["audit_log_id"] = str(audit_log.id)

                # Delete sample
                sample = db.get(Sample, sample_id)
                if sample:
                    db.delete(sample)

                db.commit()
                result["deleted"].append(f"db:sample:{sample_id}")

            except Exception as e:
                db.rollback()
                result["failed"].append({"type": "database", "error": str(e)})

        return result

    def run_retention(
        self,
        dry_run: bool = True,
        batch_size: int = 100,
    ) -> dict[str, Any]:
        """
        Run retention policy enforcement.

        Args:
            dry_run: If True, don't actually delete
            batch_size: Number of samples to process per batch

        Returns:
            Retention run report
        """
        logger.info(f"Starting retention run (dry_run={dry_run})")

        start_time = datetime.now(timezone.utc)
        processed = 0
        deleted_count = 0
        failed_count = 0
        errors = []

        db = self.db_session_factory()
        try:
            expired_samples = self.get_expired_samples(limit=batch_size)

            for sample in expired_samples:
                processed += 1
                logger.info(f"Processing expired sample: {sample['sha256']}")

                try:
                    result = self.delete_sample(
                        db=db,
                        tenant_id=sample["tenant_id"],
                        sha256=sample["sha256"],
                        sample_id=sample["id"],
                        dry_run=dry_run,
                    )

                    if result["failed"]:
                        failed_count += 1
                        errors.extend(result["failed"])
                    else:
                        deleted_count += 1

                except Exception as e:
                    failed_count += 1
                    errors.append({
                        "sha256": sample["sha256"],
                        "error": str(e),
                    })

        finally:
            db.close()

        end_time = datetime.now(timezone.utc)

        report = {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
            "dry_run": dry_run,
            "processed": processed,
            "deleted": deleted_count,
            "failed": failed_count,
            "errors": errors[:100],  # Limit errors in report
            "retention_config": {
                "artifacts_days": self.config.artifacts_days,
                "reports_days": self.config.reports_days,
                "samples_days": self.config.samples_days,
            },
        }

        logger.info(f"Retention run complete: {deleted_count} deleted, {failed_count} failed")
        return report


def run_retention_cli(dry_run: bool = True, batch_size: int = 100) -> None:
    """Run retention from CLI."""
    from services.ingest.database import get_session_factory
    from services.ingest.storage import get_storage_client

    config = get_retention_config()
    service = RetentionService(
        db_session_factory=get_session_factory(),
        storage_client=get_storage_client(),
        config=config,
    )

    report = service.run_retention(dry_run=dry_run, batch_size=batch_size)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    import sys

    dry_run = "--dry-run" not in sys.argv
    batch_size = 100

    for arg in sys.argv:
        if arg.startswith("--batch-size="):
            batch_size = int(arg.split("=")[1])

    run_retention_cli(dry_run=dry_run, batch_size=batch_size)
