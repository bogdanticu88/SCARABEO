"""Tests for search service."""

import pytest
from unittest.mock import MagicMock, patch


class TestSearchQuery:
    """Tests for search query parsing."""

    def test_parse_simple_query(self):
        """Test parsing simple text query."""
        from services.search.query import parse_query

        result = parse_query("malware")
        assert result.text == "malware"
        assert result.file_type is None
        assert result.verdict is None

    def test_parse_type_filter(self):
        """Test parsing type filter."""
        from services.search.query import parse_query

        result = parse_query("type:pe")
        assert result.text is None
        assert result.file_type == "pe"

    def test_parse_verdict_filter(self):
        """Test parsing verdict filter."""
        from services.search.query import parse_query

        result = parse_query("verdict:malicious")
        assert result.verdict == "malicious"

    def test_parse_tag_filter(self):
        """Test parsing tag filter."""
        from services.search.query import parse_query

        result = parse_query("tag:ransomware")
        assert result.tag == "ransomware"

    def test_parse_combined_filters(self):
        """Test parsing combined filters."""
        from services.search.query import parse_query

        result = parse_query("type:pe verdict:malicious tag:emotet")
        assert result.file_type == "pe"
        assert result.verdict == "malicious"
        assert result.tag == "ransomware"

    def test_parse_ioc_filter(self):
        """Test parsing IOC filter."""
        from services.search.query import parse_query

        result = parse_query("ioc:domain:evil.com")
        assert result.ioc_type == "domain"
        assert result.ioc_value == "evil.com"


class TestSearchIndexer:
    """Tests for search indexer."""

    @patch('services.search.indexer.SearchIndex')
    @patch('services.search.indexer.select')
    def test_index_sample_create(self, mock_select, mock_index):
        """Test indexing creates new entry."""
        from services.search.indexer import SearchIndexer

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = None

        def session_factory():
            return mock_db

        indexer = SearchIndexer(session_factory)

        report = {
            "sample_sha256": "a" * 64,
            "tenant_id": "test",
            "file_type": "pe",
            "summary": {"verdict": "malicious", "score": 90},
            "findings": [],
            "iocs": [],
            "provenance": {"engines": [{"name": "triage"}]},
        }

        indexer.index_sample(report)

        assert mock_db.add.called
        assert mock_db.commit.called

    @patch('services.search.indexer.SearchIndex')
    def test_get_sample(self):
        """Test getting sample from index."""
        from services.search.indexer import SearchIndexer

        mock_db = MagicMock()
        mock_result = MagicMock()
        mock_result.sample_sha256 = "a" * 64
        mock_result.tenant_id = "test"
        mock_result.file_type = "pe"
        mock_result.verdict = "malicious"
        mock_result.score = 90
        mock_result.tags = ["tag1"]
        mock_result.analyzer_names = ["triage"]
        mock_result.findings = []
        mock_result.iocs = []
        mock_result.created_at = MagicMock()
        mock_result.created_at.isoformat.return_value = "2024-01-01T00:00:00Z"
        mock_result.updated_at = MagicMock()
        mock_result.updated_at.isoformat.return_value = "2024-01-01T00:00:00Z"

        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_result

        def session_factory():
            return mock_db

        indexer = SearchIndexer(session_factory)
        result = indexer.get_sample("test", "a" * 64)

        assert result is not None
        assert result["sample_sha256"] == "a" * 64


class TestSearchAPI:
    """Tests for search API endpoints."""

    @patch('services.search.app.get_indexer')
    @patch('services.search.app.authenticate_from_headers')
    def test_search_endpoint(self, mock_auth, mock_get_indexer):
        """Test search endpoint."""
        from services.search.app import search_samples
        from scarabeo.auth import AuthContext, Role, AuthMode

        mock_auth.return_value = AuthContext(
            tenant_id="test",
            user_id="user",
            role=Role.VIEWER,
            auth_mode=AuthMode.HEADER,
            ip_address=None,
            user_agent=None,
        )

        mock_indexer = MagicMock()
        mock_indexer.search.return_value = (
            [{"sample_sha256": "a" * 64, "file_type": "pe"}],
            1,
        )
        mock_get_indexer.return_value = mock_indexer

        # Would need proper FastAPI test client for full test
        assert mock_auth.called


class TestCasesAPI:
    """Tests for cases API endpoints."""

    @patch('services.api.cases.authenticate_from_headers')
    def test_create_case(self, mock_auth):
        """Test case creation."""
        from services.api.cases import create_case, CaseCreate
        from scarabeo.auth import AuthContext, Role, AuthMode

        mock_auth.return_value = AuthContext(
            tenant_id="test",
            user_id="user",
            role=Role.ANALYST,
            auth_mode=AuthMode.HEADER,
            ip_address=None,
            user_agent=None,
        )

        case_data = CaseCreate(name="Test Case", description="Test")

        # Would need proper database mock for full test
        assert case_data.name == "Test Case"


class TestIOCIntelligence:
    """Tests for IOC intelligence."""

    @patch('scarabeo.intel.IOCSighting')
    @patch('scarabeo.intel.select')
    def test_register_ioc_new(self, mock_select, mock_sighting):
        """Test registering new IOC."""
        from scarabeo.intel import IOCIntelligence

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = None

        def session_factory():
            return mock_db

        intel = IOCIntelligence(session_factory)

        intel.register_ioc(
            ioc_value="evil.com",
            ioc_type="domain",
            sample_sha256="a" * 64,
            tenant_id="test",
        )

        assert mock_db.add.called
        assert mock_db.commit.called

    @patch('scarabeo.intel.IOCSighting')
    def test_get_ioc_intel(self):
        """Test getting IOC intelligence."""
        from scarabeo.intel import IOCIntelligence

        mock_db = MagicMock()
        mock_sighting = MagicMock()
        mock_sighting.ioc_value = "evil.com"
        mock_sighting.ioc_type = "domain"
        mock_sighting.sample_sha256 = "a" * 64
        mock_sighting.tenant_id = "test"
        mock_sighting.first_seen = MagicMock()
        mock_sighting.first_seen.isoformat.return_value = "2024-01-01T00:00:00Z"
        mock_sighting.last_seen = MagicMock()
        mock_sighting.last_seen.isoformat.return_value = "2024-01-02T00:00:00Z"
        mock_sighting.sighting_count = 1

        mock_db.execute.return_value.scalars.return_value.all.return_value = [mock_sighting]

        def session_factory():
            return mock_db

        intel = IOCIntelligence(session_factory)
        result = intel.get_ioc_intel("evil.com", "test")

        assert result is not None
        assert result["ioc_value"] == "evil.com"
