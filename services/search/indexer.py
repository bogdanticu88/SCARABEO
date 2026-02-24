"""Search indexer for Postgres backend."""

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from services.search.models import SearchIndex

logger = logging.getLogger(__name__)


class SearchIndexer:
    """Index samples for search (Postgres backend)."""

    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory

    def index_sample(self, report: dict) -> None:
        """
        Index a sample report for search.

        Args:
            report: Analysis report dictionary
        """
        db = self.db_session_factory()
        try:
            # Extract data from report
            sample_sha256 = report.get("sample_sha256")
            tenant_id = report.get("tenant_id")
            file_type = report.get("file_type", "unknown")
            summary = report.get("summary", {})
            findings = report.get("findings", [])
            iocs = report.get("iocs", [])
            artifacts = report.get("artifacts", [])
            provenance = report.get("provenance", {})

            # Extract analyzer names from provenance
            analyzer_names = [
                engine.get("name")
                for engine in provenance.get("engines", [])
            ]

            # Extract tags from findings
            tags = []
            for finding in findings:
                tags.extend(finding.get("tags", []))
            tags = list(set(tags))

            # Create or update index entry
            existing = db.execute(
                select(SearchIndex).where(SearchIndex.sample_sha256 == sample_sha256)
            ).scalar_one_or_none()

            if existing:
                # Update existing
                existing.file_type = file_type
                existing.findings = findings
                existing.iocs = iocs
                existing.analyzer_names = analyzer_names
                existing.tags = tags
                existing.verdict = summary.get("verdict")
                existing.score = summary.get("score")
                existing.updated_at = datetime.now(timezone.utc)
            else:
                # Create new
                index_entry = SearchIndex(
                    sample_sha256=sample_sha256,
                    tenant_id=tenant_id,
                    file_type=file_type,
                    findings=findings,
                    iocs=iocs,
                    analyzer_names=analyzer_names,
                    tags=tags,
                    verdict=summary.get("verdict"),
                    score=summary.get("score"),
                )
                db.add(index_entry)

            db.commit()
            logger.info(f"Indexed sample: {sample_sha256[:16]}...")

        except Exception as e:
            db.rollback()
            logger.error(f"Failed to index sample: {e}")
        finally:
            db.close()

    def delete_sample(self, sample_sha256: str) -> None:
        """
        Remove sample from index.

        Args:
            sample_sha256: Sample SHA256 hash
        """
        db = self.db_session_factory()
        try:
            db.execute(
                delete(SearchIndex).where(SearchIndex.sample_sha256 == sample_sha256)
            )
            db.commit()
            logger.info(f"Deleted sample from index: {sample_sha256[:16]}...")
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to delete sample from index: {e}")
        finally:
            db.close()

    def search(
        self,
        tenant_id: str,
        query: str | None = None,
        file_type: str | None = None,
        verdict: str | None = None,
        tag: str | None = None,
        page: int = 1,
        per_page: int = 20,
    ) -> tuple[list[dict], int]:
        """
        Search indexed samples.

        Args:
            tenant_id: Tenant identifier
            query: Search query (matches sha256, findings, tags)
            file_type: Filter by file type
            verdict: Filter by verdict
            tag: Filter by tag
            page: Page number
            per_page: Items per page

        Returns:
            Tuple of (results, total_count)
        """
        db = self.db_session_factory()
        try:
            # Local import ensures the real model class is used even when module-level
            # name is patched during testing (SQLAlchemy 2.x requires a real model).
            from services.search.models import SearchIndex  # noqa: PLC0415
            # Build query
            stmt = select(SearchIndex).where(SearchIndex.tenant_id == tenant_id)

            if file_type:
                stmt = stmt.where(SearchIndex.file_type == file_type)

            if verdict:
                stmt = stmt.where(SearchIndex.verdict == verdict)

            if tag:
                stmt = stmt.where(SearchIndex.tags.contains([tag]))

            if query:
                # Simple text search - match sha256 prefix or tags
                query_lower = query.lower()
                stmt = stmt.where(
                    (SearchIndex.sample_sha256.like(f"{query_lower}%")) |
                    (SearchIndex.tags.contains([query])) |
                    (SearchIndex.file_type.like(f"%{query_lower}%"))
                )

            # Count total
            count_stmt = select(SearchIndex.id).select_from(
                stmt.subquery()
            )
            total = db.execute(count_stmt).scalars().count()

            # Order by created_at desc
            stmt = stmt.order_by(SearchIndex.created_at.desc())

            # Apply pagination
            offset = (page - 1) * per_page
            stmt = stmt.offset(offset).limit(per_page)

            results = db.execute(stmt).scalars().all()

            return [
                {
                    "sample_sha256": r.sample_sha256,
                    "tenant_id": r.tenant_id,
                    "file_type": r.file_type,
                    "verdict": r.verdict,
                    "score": r.score,
                    "tags": r.tags or [],
                    "analyzer_names": r.analyzer_names or [],
                    "created_at": r.created_at.isoformat(),
                }
                for r in results
            ], total

        finally:
            db.close()

    def get_sample(self, tenant_id: str, sample_sha256: str) -> dict | None:
        """
        Get indexed sample by SHA256.

        Args:
            tenant_id: Tenant identifier
            sample_sha256: Sample SHA256 hash

        Returns:
            Sample index entry or None
        """
        db = self.db_session_factory()
        try:
            result = db.execute(
                select(SearchIndex).where(
                    SearchIndex.tenant_id == tenant_id,
                    SearchIndex.sample_sha256 == sample_sha256,
                )
            ).scalar_one_or_none()

            if result:
                return {
                    "sample_sha256": result.sample_sha256,
                    "tenant_id": result.tenant_id,
                    "file_type": result.file_type,
                    "findings": result.findings or [],
                    "iocs": result.iocs or [],
                    "analyzer_names": result.analyzer_names or [],
                    "tags": result.tags or [],
                    "verdict": result.verdict,
                    "score": result.score,
                    "created_at": result.created_at.isoformat(),
                    "updated_at": result.updated_at.isoformat(),
                }
            return None

        finally:
            db.close()

    def get_recent(
        self,
        tenant_id: str,
        limit: int = 20,
    ) -> list[dict]:
        """
        Get recent samples.

        Args:
            tenant_id: Tenant identifier
            limit: Maximum number of samples

        Returns:
            List of recent samples
        """
        db = self.db_session_factory()
        try:
            results = db.execute(
                select(SearchIndex)
                .where(SearchIndex.tenant_id == tenant_id)
                .order_by(SearchIndex.created_at.desc())
                .limit(limit)
            ).scalars().all()

            return [
                {
                    "sample_sha256": r.sample_sha256,
                    "file_type": r.file_type,
                    "verdict": r.verdict,
                    "score": r.score,
                    "created_at": r.created_at.isoformat(),
                }
                for r in results
            ]

        finally:
            db.close()
