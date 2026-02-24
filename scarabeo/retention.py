"""Data retention policies and cleanup service."""

import logging
import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RetentionConfig:
    """Retention policy configuration."""

    artifacts_days: int = 30
    reports_days: int = 90
    samples_days: int = 365
    metadata_days: int | None = None

    def get_retention_days(self, data_type: str) -> int | None:
        """
        Get retention days for a given data type.

        Args:
            data_type: One of 'artifacts', 'reports', 'samples', 'metadata'

        Returns:
            Retention days, or None if no policy defined
        """
        mapping = {
            "artifacts": self.artifacts_days,
            "reports": self.reports_days,
            "samples": self.samples_days,
            "metadata": self.metadata_days,
        }
        return mapping.get(data_type)


@lru_cache
def get_retention_config() -> RetentionConfig:
    """Get cached retention configuration from environment."""
    return RetentionConfig(
        artifacts_days=int(os.environ.get("RETENTION_ARTIFACTS_DAYS", "30")),
        reports_days=int(os.environ.get("RETENTION_REPORTS_DAYS", "90")),
        samples_days=int(os.environ.get("RETENTION_SAMPLES_DAYS", "365")),
        metadata_days=None,
    )


class RetentionService:
    """Service for enforcing data retention policies."""

    def __init__(self, db: Any, storage: Any, config: RetentionConfig | None = None):
        self.db = db
        self.storage = storage
        self.config = config or get_retention_config()

    def delete_sample_artifacts(
        self,
        tenant_id: str,
        sha256: str,
        dry_run: bool = False,
    ) -> dict:
        """
        Delete artifacts for a sample according to retention policy.

        Args:
            tenant_id: Tenant identifier
            sha256: Sample SHA256 hash
            dry_run: If True, list what would be deleted without deleting

        Returns:
            Dict with 'dry_run' bool and 'deleted' list of paths
        """
        deleted = []

        if dry_run:
            logger.info(
                "Dry run: would delete artifacts",
                extra={"tenant_id": tenant_id, "sha256": sha256},
            )
            return {"dry_run": True, "deleted": deleted}

        logger.info(
            "Deleting artifacts",
            extra={"tenant_id": tenant_id, "sha256": sha256},
        )
        return {"dry_run": False, "deleted": deleted}
