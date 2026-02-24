"""IOC Intelligence and correlation module."""

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from services.search.models import IOCSighting

logger = logging.getLogger(__name__)


class IOCIntelligence:
    """IOC intelligence tracking and correlation."""

    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory

    def register_ioc(
        self,
        ioc_value: str,
        ioc_type: str,
        sample_sha256: str,
        tenant_id: str,
        metadata: dict | None = None,
    ) -> None:
        """
        Register an IOC sighting.

        Args:
            ioc_value: IOC value
            ioc_type: IOC type (ip, domain, url, etc.)
            sample_sha256: Sample containing the IOC
            tenant_id: Tenant identifier
            metadata: Additional metadata
        """
        db = self.db_session_factory()
        try:
            now = datetime.now(timezone.utc)

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
                stmt = (
                    update(IOCSighting)
                    .where(IOCSighting.id == existing.id)
                    .values(last_seen=now)
                )
                db.execute(stmt)
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
                    ioc_metadata=metadata,
                )
                db.add(sighting)

            db.commit()
            logger.debug(f"Registered IOC: {ioc_type}:{ioc_value[:32]}...")

        except Exception as e:
            db.rollback()
            logger.error(f"Failed to register IOC: {e}")
        finally:
            db.close()

    def register_iocs_from_report(
        self,
        report: dict,
    ) -> int:
        """
        Register all IOCs from an analysis report.

        Args:
            report: Analysis report dictionary

        Returns:
            Number of IOCs registered
        """
        iocs = report.get("iocs", [])
        sample_sha256 = report.get("sample_sha256")
        tenant_id = report.get("tenant_id")

        count = 0
        for ioc in iocs:
            try:
                self.register_ioc(
                    ioc_value=ioc.get("value", ""),
                    ioc_type=ioc.get("type", "unknown"),
                    sample_sha256=sample_sha256,
                    tenant_id=tenant_id,
                    metadata=ioc,
                )
                count += 1
            except Exception as e:
                logger.error(f"Failed to register IOC: {e}")

        logger.info(f"Registered {count} IOCs from report: {sample_sha256[:16]}...")
        return count

    def get_ioc_intel(
        self,
        ioc_value: str,
        tenant_id: str | None = None,
    ) -> dict | None:
        """
        Get intelligence data for an IOC.

        Args:
            ioc_value: IOC value
            tenant_id: Optional tenant filter

        Returns:
            IOC intelligence data or None
        """
        db = self.db_session_factory()
        try:
            stmt = select(IOCSighting).where(IOCSighting.ioc_value == ioc_value)

            if tenant_id:
                stmt = stmt.where(IOCSighting.tenant_id == tenant_id)

            sightings = db.execute(stmt).scalars().all()

            if not sightings:
                return None

            # Aggregate data
            samples = list(set(s.sample_sha256 for s in sightings))
            tenants = list(set(s.tenant_id for s in sightings))
            first_seen = min(s.first_seen for s in sightings)
            last_seen = max(s.last_seen for s in sightings)
            total_count = sum(s.sighting_count for s in sightings)
            ioc_type = sightings[0].ioc_type

            return {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "samples": samples,
                "tenants": tenants,
                "first_seen": first_seen.isoformat(),
                "last_seen": last_seen.isoformat(),
                "total_sightings": total_count,
                "sample_count": len(samples),
            }

        finally:
            db.close()

    def search_iocs(
        self,
        query: str,
        ioc_type: str | None = None,
        tenant_id: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Search for IOCs.

        Args:
            query: Search query (partial match)
            ioc_type: Optional type filter
            tenant_id: Optional tenant filter
            limit: Maximum results

        Returns:
            List of IOC summaries
        """
        db = self.db_session_factory()
        try:
            stmt = select(IOCSighting).where(
                IOCSighting.ioc_value.ilike(f"%{query}%")
            )

            if ioc_type:
                stmt = stmt.where(IOCSighting.ioc_type == ioc_type)

            if tenant_id:
                stmt = stmt.where(IOCSighting.tenant_id == tenant_id)

            stmt = stmt.order_by(IOCSighting.sighting_count.desc()).limit(limit)

            sightings = db.execute(stmt).scalars().all()

            return [
                {
                    "ioc_value": s.ioc_value,
                    "ioc_type": s.ioc_type,
                    "sighting_count": s.sighting_count,
                    "first_seen": s.first_seen.isoformat(),
                    "last_seen": s.last_seen.isoformat(),
                }
                for s in sightings
            ]

        finally:
            db.close()

    def get_tenant_ioc_stats(
        self,
        tenant_id: str,
    ) -> dict:
        """
        Get IOC statistics for a tenant.

        Args:
            tenant_id: Tenant identifier

        Returns:
            IOC statistics
        """
        db = self.db_session_factory()
        try:
            from sqlalchemy import func

            # Total unique IOCs
            total_stmt = select(func.count(func.distinct(IOCSighting.ioc_value))).where(
                IOCSighting.tenant_id == tenant_id
            )
            total = db.execute(total_stmt).scalar()

            # By type
            type_stmt = select(
                IOCSighting.ioc_type,
                func.count(func.distinct(IOCSighting.ioc_value)),
            ).where(
                IOCSighting.tenant_id == tenant_id
            ).group_by(IOCSighting.ioc_type)

            by_type = {
                row[0]: row[1]
                for row in db.execute(type_stmt).all()
            }

            return {
                "tenant_id": tenant_id,
                "total_unique_iocs": total,
                "by_type": by_type,
            }

        finally:
            db.close()


def get_ioc_intelligence(db_session_factory) -> IOCIntelligence:
    """Get IOC intelligence instance."""
    return IOCIntelligence(db_session_factory)
