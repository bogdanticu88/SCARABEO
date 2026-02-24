"""Tests for similarity clustering."""

import pytest
from unittest.mock import MagicMock, patch
import uuid


class TestSimilarityFunctions:
    """Tests for similarity computation functions."""

    def test_tlsh_distance_identical(self):
        """Test TLSH distance for identical hashes."""
        from services.worker.clustering import compute_tlsh_distance

        hash_val = "T1A2B3C4D5E6F7890ABCDEF1234567890ABCDEF1234567890ABCDEF12345678"
        distance = compute_tlsh_distance(hash_val, hash_val)
        assert distance == 0

    def test_tlsh_distance_different(self):
        """Test TLSH distance for different hashes."""
        from services.worker.clustering import compute_tlsh_distance

        hash1 = "T1A2B3C4D5E6F7890ABCDEF1234567890ABCDEF1234567890ABCDEF12345678"
        hash2 = "T1B2C3D4E5F6A7890ABCDEF1234567890ABCDEF1234567890ABCDEF12345678"
        distance = compute_tlsh_distance(hash1, hash2)
        assert distance > 0

    def test_ssdeep_score_identical(self):
        """Test SSDEEP score for identical hashes."""
        from services.worker.clustering import compute_ssdeep_score

        hash_val = "12288:abcdefghijklmnop:12288"
        score = compute_ssdeep_score(hash_val, hash_val)
        assert score == 100

    def test_imphash_match(self):
        """Test imphash exact match."""
        from services.worker.clustering import compute_imphash_match

        hash_val = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        score = compute_imphash_match(hash_val, hash_val)
        assert score == 100

    def test_imphash_no_match(self):
        """Test imphash no match."""
        from services.worker.clustering import compute_imphash_match

        hash1 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        hash2 = "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6"
        score = compute_imphash_match(hash1, hash2)
        assert score == 0

    def test_sha256_prefix_match(self):
        """Test SHA256 prefix match."""
        from services.worker.clustering import compute_sha256_prefix_match

        sha1 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
        sha2 = "a1b2c3d4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2"
        # First 8 chars match
        score = compute_sha256_prefix_match(sha1, sha2)
        assert score == 100

    def test_sha256_prefix_no_match(self):
        """Test SHA256 prefix no match."""
        from services.worker.clustering import compute_sha256_prefix_match

        sha1 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
        sha2 = "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"
        score = compute_sha256_prefix_match(sha1, sha2)
        assert score == 0


class TestClusterIdGeneration:
    """Tests for deterministic cluster ID generation."""

    def test_generate_cluster_id_deterministic(self):
        """Test cluster ID is deterministic."""
        from services.worker.clustering import generate_cluster_id

        tenant_id = "test-tenant"
        algorithm = "tlsh"
        primary_sha256 = "a" * 64

        id1 = generate_cluster_id(tenant_id, algorithm, primary_sha256)
        id2 = generate_cluster_id(tenant_id, algorithm, primary_sha256)

        assert id1 == id2
        assert isinstance(id1, uuid.UUID)

    def test_generate_cluster_id_different_inputs(self):
        """Test different inputs produce different IDs."""
        from services.worker.clustering import generate_cluster_id

        id1 = generate_cluster_id("tenant-a", "tlsh", "a" * 64)
        id2 = generate_cluster_id("tenant-b", "tlsh", "a" * 64)
        id3 = generate_cluster_id("tenant-a", "ssdeep", "a" * 64)
        id4 = generate_cluster_id("tenant-a", "tlsh", "b" * 64)

        assert id1 != id2
        assert id1 != id3
        assert id1 != id4


class TestClusteringService:
    """Tests for ClusteringService."""

    @patch('services.worker.clustering.Cluster')
    @patch('services.worker.clustering.ClusterMember')
    def test_process_sample_no_hashes(self, mock_member, mock_cluster):
        """Test processing sample with no similarity hashes."""
        from services.worker.clustering import ClusteringService

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = None

        def session_factory():
            return mock_db

        service = ClusteringService(session_factory)

        # Mock get_sample_similarity_hashes to return empty
        service.get_sample_similarity_hashes = MagicMock(return_value={})

        clusters = service.process_sample_for_clustering("test-tenant", "a" * 64)

        assert clusters == []

    def test_get_threshold_for_algorithm(self):
        """Test threshold retrieval for different algorithms."""
        from services.worker.clustering import ClusteringService

        mock_db = MagicMock()

        def session_factory():
            return mock_db

        service = ClusteringService(session_factory)

        assert service.get_threshold_for_algorithm("tlsh") > 0
        assert service.get_threshold_for_algorithm("ssdeep") > 0
        assert service.get_threshold_for_algorithm("imphash") > 0
        assert service.get_threshold_for_algorithm("sha256-prefix") == 100


class TestClusterAPI:
    """Tests for cluster API endpoints."""

    @patch('services.api.clusters.get_session')
    @patch('services.api.clusters.authenticate_from_headers')
    def test_list_clusters(self, mock_auth, mock_session):
        """Test listing clusters."""
        from services.api.clusters import list_clusters
        from scarabeo.auth import AuthContext, Role, AuthMode

        mock_auth.return_value = AuthContext(
            tenant_id="test",
            user_id="user123",
            role=Role.VIEWER,
            auth_mode=AuthMode.HEADER,
            ip_address=None,
            user_agent=None,
        )

        mock_db = MagicMock()
        mock_cluster = MagicMock()
        mock_cluster.cluster_id = uuid.uuid4()
        mock_cluster.tenant_id = "test"
        mock_cluster.algorithm = "tlsh"
        mock_cluster.threshold = 30
        mock_cluster.primary_sample_sha256 = "a" * 64
        mock_cluster.created_at = MagicMock()
        mock_cluster.created_at.isoformat.return_value = "2024-01-01T00:00:00Z"

        mock_db.execute.return_value.scalars.return_value.all.return_value = [mock_cluster]
        mock_session.return_value = mock_db

        result = list_clusters(None, 1, 20, mock_auth(), mock_db)

        assert isinstance(result, list)

    @patch('services.api.clusters.get_session')
    @patch('services.api.clusters.authenticate_from_headers')
    def test_get_cluster_not_found(self, mock_auth, mock_session):
        """Test getting non-existent cluster."""
        from services.api.clusters import get_cluster
        from scarabeo.auth import AuthContext, Role, AuthMode
        from fastapi import HTTPException

        mock_auth.return_value = AuthContext(
            tenant_id="test",
            user_id="user123",
            role=Role.VIEWER,
            auth_mode=AuthMode.HEADER,
            ip_address=None,
            user_agent=None,
        )

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = None
        mock_session.return_value = mock_db

        with pytest.raises(HTTPException) as exc_info:
            get_cluster(str(uuid.uuid4()), mock_auth(), mock_db)

        assert exc_info.value.status_code == 404


class TestTenantIsolation:
    """Tests for tenant isolation in clustering."""

    @patch('services.api.clusters.get_session')
    @patch('services.api.clusters.authenticate_from_headers')
    def test_cluster_tenant_isolation(self, mock_auth, mock_session):
        """Test clusters are tenant-isolated."""
        from services.api.clusters import get_cluster
        from scarabeo.auth import AuthContext, Role, AuthMode
        from fastapi import HTTPException
        import uuid

        mock_auth.return_value = AuthContext(
            tenant_id="tenant-a",
            user_id="user123",
            role=Role.VIEWER,
            auth_mode=AuthMode.HEADER,
            ip_address=None,
            user_agent=None,
        )

        mock_db = MagicMock()
        # Cluster belongs to different tenant
        mock_db.execute.return_value.scalar_one_or_none.return_value = None
        mock_session.return_value = mock_db

        with pytest.raises(HTTPException) as exc_info:
            get_cluster(str(uuid.uuid4()), mock_auth(), mock_db)

        assert exc_info.value.status_code == 404
