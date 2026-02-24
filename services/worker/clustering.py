"""Similarity clustering service for SCARABEO."""

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.ingest.models import Cluster, ClusterMember

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CLUSTER_SIZE = 500  # Number of recent samples to compare against
DEFAULT_TLSH_THRESHOLD = 30  # Lower = more similar (TLSH distance)
DEFAULT_SSDEEP_THRESHOLD = 90  # Higher = more similar (match score 0-100)
DEFAULT_IMPHASH_THRESHOLD = 100  # Exact match only


class SimilarityCluster:
    """Represents a similarity cluster."""

    def __init__(
        self,
        cluster_id: uuid.UUID,
        tenant_id: str,
        algorithm: str,
        threshold: int,
        primary_sample_sha256: str,
    ):
        self.cluster_id = cluster_id
        self.tenant_id = tenant_id
        self.algorithm = algorithm
        self.threshold = threshold
        self.primary_sample_sha256 = primary_sample_sha256
        self.created_at = datetime.now(timezone.utc)


def generate_cluster_id(tenant_id: str, algorithm: str, primary_sha256: str) -> uuid.UUID:
    """
    Generate deterministic cluster ID using UUID5.

    Args:
        tenant_id: Tenant identifier
        algorithm: Clustering algorithm
        primary_sha256: Primary sample SHA256

    Returns:
        Deterministic UUID
    """
    namespace = uuid.NAMESPACE_DNS
    name = f"{tenant_id}:{algorithm}:{primary_sha256}"
    return uuid.uuid5(namespace, name)


def compute_tlsh_distance(hash1: str, hash2: str) -> int:
    """
    Compute TLSH distance between two hashes.

    Args:
        hash1: First TLSH hash
        hash2: Second TLSH hash

    Returns:
        Distance (lower = more similar)
    """
    if not hash1 or not hash2:
        return 100  # Max distance

    # Remove T prefix if present
    hash1 = hash1.lstrip("T")
    hash2 = hash2.lstrip("T")

    if len(hash1) != len(hash2):
        return 100

    # Simple Hamming distance on hex characters
    distance = 0
    for c1, c2 in zip(hash1, hash2):
        if c1 != c2:
            # Calculate hex digit distance
            try:
                v1 = int(c1, 16)
                v2 = int(c2, 16)
                distance += abs(v1 - v2)
            except ValueError:
                distance += 1

    return min(distance, 100)


def compute_ssdeep_score(hash1: str, hash2: str) -> int:
    """
    Compute SSDEEP match score.

    Args:
        hash1: First SSDEEP hash
        hash2: Second SSDEEP hash

    Returns:
        Score (0-100, higher = more similar)
    """
    if not hash1 or not hash2:
        return 0

    # Parse SSDEEP format: chunksize:hash:chunksize
    parts1 = hash1.split(":")
    parts2 = hash2.split(":")

    if len(parts1) != 3 or len(parts2) != 3:
        return 0

    chunksize1, hash1_str, _ = parts1
    chunksize2, hash2_str, _ = parts2

    # Check if chunk sizes are compatible (one is double the other or equal)
    try:
        cs1 = int(chunksize1)
        cs2 = int(chunksize2)
    except ValueError:
        return 0

    if cs1 != cs2 and cs1 != cs2 * 2 and cs2 != cs1 * 2:
        return 0

    # Calculate longest common substring ratio
    if not hash1_str or not hash2_str:
        return 0

    # Simple similarity based on common characters
    common = sum(1 for c in hash1_str if c in hash2_str)
    max_len = max(len(hash1_str), len(hash2_str))

    if max_len == 0:
        return 0

    return int((common / max_len) * 100)


def compute_imphash_match(hash1: str, hash2: str) -> int:
    """
    Compute imphash match score.

    Args:
        hash1: First imphash
        hash2: Second imphash

    Returns:
        100 if exact match, 0 otherwise
    """
    if not hash1 or not hash2:
        return 0

    return 100 if hash1.lower() == hash2.lower() else 0


def compute_sha256_prefix_match(sha256_1: str, sha256_2: str, prefix_len: int = 8) -> int:
    """
    Compute SHA256 prefix match score.

    Args:
        sha256_1: First SHA256 hash
        sha256_2: Second SHA256 hash
        prefix_len: Length of prefix to compare

    Returns:
        100 if prefix matches, 0 otherwise
    """
    if not sha256_1 or not sha256_2:
        return 0

    prefix1 = sha256_1[:prefix_len].lower()
    prefix2 = sha256_2[:prefix_len].lower()

    return 100 if prefix1 == prefix2 else 0


class ClusteringService:
    """Service for similarity clustering."""

    def __init__(self, db_session_factory, cluster_size: int = DEFAULT_CLUSTER_SIZE):
        self.db_session_factory = db_session_factory
        self.cluster_size = cluster_size

    def get_recent_samples(
        self,
        tenant_id: str,
        exclude_sha256: str,
        limit: int | None = None,
    ) -> list[dict]:
        """
        Get recent samples for clustering comparison.

        Args:
            tenant_id: Tenant identifier
            exclude_sha256: SHA256 to exclude (current sample)
            limit: Maximum number of samples

        Returns:
            List of sample data with similarity hashes
        """
        db = self.db_session_factory()
        try:
            from services.ingest.models import Sample

            limit = limit or self.cluster_size

            stmt = (
                select(Sample)
                .where(
                    Sample.tenant_id == tenant_id,
                    Sample.sha256 != exclude_sha256,
                )
                .order_by(Sample.created_at.desc())
                .limit(limit)
            )

            samples = db.execute(stmt).scalars().all()

            return [
                {
                    "sha256": s.sha256,
                    "file_type": s.file_type,
                    "created_at": s.created_at,
                }
                for s in samples
            ]
        finally:
            db.close()

    def get_sample_similarity_hashes(
        self,
        sample_sha256: str,
    ) -> dict:
        """
        Get similarity hashes for a sample from its report.

        Args:
            sample_sha256: Sample SHA256

        Returns:
            Dictionary of similarity hashes
        """
        db = self.db_session_factory()
        try:
            from services.ingest.models import Job

            # Get latest job with report
            stmt = (
                select(Job)
                .where(Job.result.isnot(None))
                .order_by(Job.created_at.desc())
            )

            job = db.execute(stmt).scalar_one_or_none()

            if not job or not job.result:
                return {}

            try:
                import json
                report = json.loads(job.result)
            except (json.JSONDecodeError, TypeError):
                return {}

            hashes = report.get("hashes", {})

            return {
                "tlsh": hashes.get("tlsh"),
                "ssdeep": hashes.get("ssdeep"),
                "imphash": hashes.get("imphash"),
                "sha256": sample_sha256,
            }
        finally:
            db.close()

    def find_matching_cluster(
        self,
        tenant_id: str,
        similarity_hashes: dict,
        algorithm: str,
    ) -> tuple[str | None, int]:
        """
        Find existing cluster that sample matches.

        Args:
            tenant_id: Tenant identifier
            similarity_hashes: Sample similarity hashes
            algorithm: Clustering algorithm

        Returns:
            Tuple of (cluster_id or None, match_score)
        """
        db = self.db_session_factory()
        try:
            # Get clusters for this tenant and algorithm
            stmt = (
                select(Cluster)
                .where(
                    Cluster.tenant_id == tenant_id,
                    Cluster.algorithm == algorithm,
                )
                .order_by(Cluster.created_at.desc())
            )

            clusters = db.execute(stmt).scalars().all()

            for cluster in clusters:
                # Get cluster members
                members_stmt = (
                    select(ClusterMember)
                    .where(ClusterMember.cluster_id == cluster.cluster_id)
                )
                members = db.execute(members_stmt).scalars().all()

                # Check similarity against each member
                for member in members:
                    member_hashes = self.get_sample_similarity_hashes(member.sample_sha256)

                    score = self.compute_similarity(
                        similarity_hashes,
                        member_hashes,
                        algorithm,
                    )

                    threshold = self.get_threshold_for_algorithm(algorithm)
                    if score >= threshold:
                        return str(cluster.cluster_id), score

            return None, 0
        finally:
            db.close()

    def compute_similarity(
        self,
        hashes1: dict,
        hashes2: dict,
        algorithm: str,
    ) -> int:
        """
        Compute similarity score between two samples.

        Args:
            hashes1: First sample hashes
            hashes2: Second sample hashes
            algorithm: Algorithm to use

        Returns:
            Similarity score (0-100)
        """
        if algorithm == "tlsh":
            return 100 - compute_tlsh_distance(
                hashes1.get("tlsh", ""),
                hashes2.get("tlsh", ""),
            )
        elif algorithm == "ssdeep":
            return compute_ssdeep_score(
                hashes1.get("ssdeep", ""),
                hashes2.get("ssdeep", ""),
            )
        elif algorithm == "imphash":
            return compute_imphash_match(
                hashes1.get("imphash", ""),
                hashes2.get("imphash", ""),
            )
        elif algorithm == "sha256-prefix":
            return compute_sha256_prefix_match(
                hashes1.get("sha256", ""),
                hashes2.get("sha256", ""),
            )

        return 0

    def get_threshold_for_algorithm(self, algorithm: str) -> int:
        """Get similarity threshold for algorithm."""
        thresholds = {
            "tlsh": 100 - DEFAULT_TLSH_THRESHOLD,  # Invert for score
            "ssdeep": DEFAULT_SSDEEP_THRESHOLD,
            "imphash": DEFAULT_IMPHASH_THRESHOLD,
            "sha256-prefix": 100,
        }
        return thresholds.get(algorithm, 50)

    def create_cluster(
        self,
        tenant_id: str,
        algorithm: str,
        primary_sha256: str,
    ) -> uuid.UUID:
        """
        Create a new cluster.

        Args:
            tenant_id: Tenant identifier
            algorithm: Clustering algorithm
            primary_sha256: Primary sample SHA256

        Returns:
            Cluster ID
        """
        db = self.db_session_factory()
        try:
            from services.ingest.models import Cluster, AuditAction, AuditLog

            cluster_id = generate_cluster_id(tenant_id, algorithm, primary_sha256)
            threshold = self.get_threshold_for_algorithm(algorithm)

            cluster = Cluster(
                cluster_id=cluster_id,
                tenant_id=tenant_id,
                algorithm=algorithm,
                threshold=threshold,
                primary_sample_sha256=primary_sha256,
            )
            db.add(cluster)

            # Audit log
            audit_log = AuditLog(
                tenant_id=tenant_id,
                action=AuditAction.JOB_CREATED,
                target_type="cluster",
                target_id=str(cluster_id),
                details_json={
                    "action": "cluster_created",
                    "algorithm": algorithm,
                    "primary_sample": primary_sha256,
                },
            )
            db.add(audit_log)
            db.commit()

            logger.info(f"Created cluster {cluster_id} for tenant {tenant_id}")
            return cluster_id

        except Exception as e:
            db.rollback()
            logger.error(f"Failed to create cluster: {e}")
            raise
        finally:
            db.close()

    def add_member_to_cluster(
        self,
        cluster_id: uuid.UUID,
        sample_sha256: str,
        score: int,
    ) -> None:
        """
        Add sample to cluster.

        Args:
            cluster_id: Cluster ID
            sample_sha256: Sample SHA256
            score: Similarity score
        """
        db = self.db_session_factory()
        try:
            member = ClusterMember(
                cluster_id=cluster_id,
                sample_sha256=sample_sha256,
                score=score,
            )
            db.add(member)
            db.commit()

            logger.info(f"Added {sample_sha256[:16]}... to cluster {cluster_id}")

        except Exception as e:
            db.rollback()
            logger.error(f"Failed to add cluster member: {e}")
        finally:
            db.close()

    def process_sample_for_clustering(
        self,
        tenant_id: str,
        sample_sha256: str,
    ) -> list[dict]:
        """
        Process a sample for clustering after analysis.

        Args:
            tenant_id: Tenant identifier
            sample_sha256: Sample SHA256

        Returns:
            List of clusters the sample was added to
        """
        # Get similarity hashes for this sample
        similarity_hashes = self.get_sample_similarity_hashes(sample_sha256)

        if not any(similarity_hashes.values()):
            logger.debug(f"No similarity hashes for {sample_sha256[:16]}...")
            return []

        clusters_added = []
        algorithms = ["tlsh", "ssdeep", "imphash", "sha256-prefix"]

        for algorithm in algorithms:
            # Check if we have this hash type
            hash_key = algorithm if algorithm != "sha256-prefix" else "sha256"
            if not similarity_hashes.get(hash_key):
                continue

            # Try to find matching cluster
            cluster_id, score = self.find_matching_cluster(
                tenant_id,
                similarity_hashes,
                algorithm,
            )

            if cluster_id:
                # Add to existing cluster
                self.add_member_to_cluster(
                    uuid.UUID(cluster_id),
                    sample_sha256,
                    score,
                )
                clusters_added.append({
                    "cluster_id": cluster_id,
                    "algorithm": algorithm,
                    "score": score,
                })
            else:
                # Create new cluster with this sample as primary
                new_cluster_id = self.create_cluster(
                    tenant_id,
                    algorithm,
                    sample_sha256,
                )
                self.add_member_to_cluster(
                    new_cluster_id,
                    sample_sha256,
                    100,  # Primary member has perfect score
                )
                clusters_added.append({
                    "cluster_id": str(new_cluster_id),
                    "algorithm": algorithm,
                    "score": 100,
                })

        return clusters_added


def get_clustering_service(db_session_factory) -> ClusteringService:
    """Get clustering service instance."""
    return ClusteringService(db_session_factory)
