"""Tests for review workflow - verdict, tags, notes, export."""

import io
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
from zipfile import ZipFile


class TestVerdictEndpoints:
    """Tests for verdict endpoints."""

    @patch('services.api.review.get_session')
    @patch('services.api.review.authenticate_from_headers')
    def test_set_verdict_success(self, mock_auth, mock_session):
        """Test setting verdict successfully."""
        from services.api.review import set_sample_verdict, VerdictRequest
        from scarabeo.auth import AuthContext, Role, AuthMode

        mock_auth.return_value = AuthContext(
            tenant_id="test",
            user_id="user123",
            role=Role.ANALYST,
            auth_mode=AuthMode.HEADER,
            ip_address=None,
            user_agent=None,
        )

        mock_db = MagicMock()
        mock_sample = MagicMock()
        mock_sample.id = "sample-id"
        mock_sample.sha256 = "a" * 64
        mock_sample.tenant_id = "test"
        mock_sample.tags = []
        mock_sample.notes_count = 0

        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_sample
        mock_session.return_value = mock_db

        verdict_data = VerdictRequest(verdict="malicious", reason="Ransomware detected")

        result = set_sample_verdict("a" * 64, verdict_data, mock_auth(), mock_db)

        assert result.verdict == "malicious"
        assert result.reason == "Ransomware detected"
        assert mock_db.execute.called
        assert mock_db.commit.called

    @patch('services.api.review.get_session')
    @patch('services.api.review.authenticate_from_headers')
    def test_set_verdict_invalid(self, mock_auth, mock_session):
        """Test setting invalid verdict."""
        from services.api.review import set_sample_verdict, VerdictRequest
        from scarabeo.auth import AuthContext, Role, AuthMode
        from fastapi import HTTPException

        mock_auth.return_value = AuthContext(
            tenant_id="test",
            user_id="user123",
            role=Role.ANALYST,
            auth_mode=AuthMode.HEADER,
            ip_address=None,
            user_agent=None,
        )

        mock_db = MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = MagicMock()
        mock_session.return_value = mock_db

        verdict_data = VerdictRequest(verdict="invalid", reason="test")

        with pytest.raises(HTTPException) as exc_info:
            set_sample_verdict("a" * 64, verdict_data, mock_auth(), mock_db)

        assert exc_info.value.status_code == 400


class TestTagEndpoints:
    """Tests for tag endpoints."""

    @patch('services.api.review.get_session')
    @patch('services.api.review.authenticate_from_headers')
    def test_add_tag_success(self, mock_auth, mock_session):
        """Test adding tag successfully."""
        from services.api.review import add_sample_tag, TagRequest
        from scarabeo.auth import AuthContext, Role, AuthMode

        mock_auth.return_value = AuthContext(
            tenant_id="test",
            user_id="user123",
            role=Role.ANALYST,
            auth_mode=AuthMode.HEADER,
            ip_address=None,
            user_agent=None,
        )

        mock_db = MagicMock()
        mock_sample = MagicMock()
        mock_sample.id = "sample-id"
        mock_sample.tags = ["existing"]

        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_sample
        mock_session.return_value = mock_db

        tag_data = TagRequest(tag="new-tag")

        result = add_sample_tag("a" * 64, tag_data, mock_auth(), mock_db)

        assert "new-tag" in result.tags
        assert "existing" in result.tags


class TestNoteEndpoints:
    """Tests for note endpoints."""

    @patch('services.api.review.get_session')
    @patch('services.api.review.authenticate_from_headers')
    def test_add_note_success(self, mock_auth, mock_session):
        """Test adding note successfully."""
        from services.api.review import add_sample_note, NoteRequest
        from scarabeo.auth import AuthContext, Role, AuthMode

        mock_auth.return_value = AuthContext(
            tenant_id="test",
            user_id="user123",
            role=Role.ANALYST,
            auth_mode=AuthMode.HEADER,
            ip_address=None,
            user_agent=None,
        )

        mock_db = MagicMock()
        mock_sample = MagicMock()
        mock_sample.id = "sample-id"
        mock_sample.notes_count = 0

        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_sample
        mock_session.return_value = mock_db

        note_data = NoteRequest(body="Test note content")

        result = add_sample_note("a" * 64, note_data, mock_auth(), mock_db)

        assert result.body == "Test note content"
        assert result.author_id == "user123"


class TestExportDeterminism:
    """Tests for export determinism."""

    def test_zip_deterministic_content(self):
        """Test that ZIP content is deterministic."""
        import json
        from io import BytesIO
        from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

        fixed_timestamp = (2024, 1, 1, 0, 0, 0)

        # Create first ZIP
        buffer1 = BytesIO()
        with ZipFile(buffer1, "w", ZIP_DEFLATED, compresslevel=6) as zf:
            info = ZipInfo("test.json", date_time=fixed_timestamp)
            info.compress_type = ZIP_DEFLATED
            zf.writestr(info, json.dumps({"key": "value"}, sort_keys=True))

        # Create second ZIP with same content
        buffer2 = BytesIO()
        with ZipFile(buffer2, "w", ZIP_DEFLATED, compresslevel=6) as zf:
            info = ZipInfo("test.json", date_time=fixed_timestamp)
            info.compress_type = ZIP_DEFLATED
            zf.writestr(info, json.dumps({"key": "value"}, sort_keys=True))

        # Compare
        assert buffer1.getvalue() == buffer2.getvalue()

    def test_zip_stable_ordering(self):
        """Test that file ordering in ZIP is stable."""
        from io import BytesIO
        from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

        fixed_timestamp = (2024, 1, 1, 0, 0, 0)
        files = ["metadata.json", "notes.json", "report.json"]

        # Create ZIP with files in order
        buffer = BytesIO()
        with ZipFile(buffer, "w", ZIP_DEFLATED, compresslevel=6) as zf:
            for filename in files:
                info = ZipInfo(filename, date_time=fixed_timestamp)
                info.compress_type = ZIP_DEFLATED
                zf.writestr(info, f"content of {filename}")

        # Verify ordering
        with ZipFile(buffer, "r") as zf:
            names = zf.namelist()
            assert names == files


class TestFindingStatusEndpoints:
    """Tests for finding status endpoints."""

    @patch('services.api.review.get_session')
    @patch('services.api.review.authenticate_from_headers')
    def test_set_finding_status_success(self, mock_auth, mock_session):
        """Test setting finding status successfully."""
        from services.api.review import set_finding_status, FindingStatusRequest
        from scarabeo.auth import AuthContext, Role, AuthMode

        mock_auth.return_value = AuthContext(
            tenant_id="test",
            user_id="user123",
            role=Role.ANALYST,
            auth_mode=AuthMode.HEADER,
            ip_address=None,
            user_agent=None,
        )

        mock_db = MagicMock()
        mock_sample = MagicMock()
        mock_sample.id = "sample-id"

        mock_db.execute.return_value.scalar_one_or_none.side_effect = [
            mock_sample,  # Sample lookup
            None,  # Finding status lookup (doesn't exist yet)
        ]
        mock_session.return_value = mock_db

        status_data = FindingStatusRequest(
            status="false_positive",
            analyst_note="Confirmed false positive"
        )

        result = set_finding_status("a" * 64, "finding-001", status_data, mock_auth(), mock_db)

        assert result.status == "false_positive"
        assert result.analyst_note == "Confirmed false positive"


class TestSearchVerdictTagFilters:
    """Tests for search with verdict and tag filters."""

    @patch('services.search.indexer.SearchIndex')
    def test_search_by_verdict(self, mock_index):
        """Test search filtered by verdict."""
        from services.search.indexer import SearchIndexer

        mock_db = MagicMock()
        mock_result = MagicMock()
        mock_result.sample_sha256 = "a" * 64
        mock_result.file_type = "pe"
        mock_result.verdict = "malicious"
        mock_result.score = 90

        mock_db.execute.return_value.scalars.return_value.all.return_value = [mock_result]

        def session_factory():
            return mock_db

        indexer = SearchIndexer(session_factory)
        results, total = indexer.search(
            tenant_id="test",
            verdict="malicious",
        )

        assert len(results) == 1
        assert results[0]["verdict"] == "malicious"

    @patch('services.search.indexer.SearchIndex')
    def test_search_by_tag(self, mock_index):
        """Test search filtered by tag."""
        from services.search.indexer import SearchIndexer

        mock_db = MagicMock()
        mock_result = MagicMock()
        mock_result.sample_sha256 = "a" * 64
        mock_result.file_type = "pe"
        mock_result.tags = ["ransomware", "emotet"]

        mock_db.execute.return_value.scalars.return_value.all.return_value = [mock_result]

        def session_factory():
            return mock_db

        indexer = SearchIndexer(session_factory)
        results, total = indexer.search(
            tenant_id="test",
            tag="ransomware",
        )

        assert len(results) == 1


class TestTenantIsolation:
    """Tests for tenant isolation in review endpoints."""

    @patch('services.api.review.get_session')
    @patch('services.api.review.authenticate_from_headers')
    def test_verdict_tenant_isolation(self, mock_auth, mock_session):
        """Test that verdict can only be set for own tenant."""
        from services.api.review import set_sample_verdict, VerdictRequest
        from scarabeo.auth import AuthContext, Role, AuthMode
        from fastapi import HTTPException

        mock_auth.return_value = AuthContext(
            tenant_id="tenant-a",
            user_id="user123",
            role=Role.ANALYST,
            auth_mode=AuthMode.HEADER,
            ip_address=None,
            user_agent=None,
        )

        mock_db = MagicMock()
        # Sample belongs to different tenant
        mock_db.execute.return_value.scalar_one_or_none.return_value = None
        mock_session.return_value = mock_db

        verdict_data = VerdictRequest(verdict="malicious")

        with pytest.raises(HTTPException) as exc_info:
            set_sample_verdict("a" * 64, verdict_data, mock_auth(), mock_db)

        assert exc_info.value.status_code == 404
