"""Tests for web console."""

import asyncio
import pytest
from unittest.mock import MagicMock, patch


_AUTH = {"tenant_id": "test", "user_id": "user123", "role": "viewer"}


class TestWebRoutes:
    """Tests for web console routes."""

    @patch('services.web.app.templates')
    @patch('services.web.app.requests.get')
    def test_home_page(self, mock_get, mock_tpl):
        """Test home page renders."""
        from services.web.app import home
        from fastapi import Request

        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        mock_tpl.TemplateResponse.return_value = MagicMock()

        mock_request = MagicMock(spec=Request)
        asyncio.run(home(mock_request, _AUTH, 20))

        assert mock_get.called

    @patch('services.web.app.templates')
    @patch('services.web.app.requests.get')
    def test_sample_detail_page(self, mock_get, mock_tpl):
        """Test sample detail page."""
        from services.web.app import sample_detail
        from fastapi import Request

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "sha256": "a" * 64,
            "file_type": "pe",
            "size_bytes": 1024,
            "clusters": [],
        }
        mock_response.raise_for_status.return_value = None
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        mock_tpl.TemplateResponse.return_value = MagicMock()

        mock_request = MagicMock(spec=Request)
        asyncio.run(sample_detail("a" * 64, mock_request, _AUTH))

        assert mock_get.called

    @patch('services.web.app.templates')
    @patch('services.web.app.requests.get')
    def test_search_page(self, mock_get, mock_tpl):
        """Test search page with a query."""
        from services.web.app import search
        from fastapi import Request

        mock_response = MagicMock()
        mock_response.json.return_value = {"items": [], "total": 0, "total_pages": 0}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        mock_tpl.TemplateResponse.return_value = MagicMock()

        mock_request = MagicMock(spec=Request)
        asyncio.run(search(mock_request, _AUTH, q="mimikatz", page=1))

        assert mock_get.called

    @patch('services.web.app.templates')
    @patch('services.web.app.requests.get')
    def test_clusters_page(self, mock_get, mock_tpl):
        """Test clusters page."""
        from services.web.app import clusters
        from fastapi import Request

        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        mock_tpl.TemplateResponse.return_value = MagicMock()

        mock_request = MagicMock(spec=Request)
        asyncio.run(clusters(mock_request, _AUTH, algorithm=""))

        assert mock_get.called


class TestWebAuth:
    """Tests for web console authentication."""

    def test_auth_required(self):
        """Auth dependency raises HTTPException when headers are missing."""
        from fastapi import HTTPException
        from scarabeo.auth import AuthError

        with patch('services.web.app.authenticate_from_headers',
                   side_effect=AuthError("Missing tenant ID", 400)):
            from services.web.app import get_auth
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(get_auth(None, None, None))
            assert exc_info.value.status_code == 400


class TestTenantIsolation:
    """Tests for tenant isolation in web console."""

    @patch('services.web.app.templates')
    @patch('services.web.app.requests.get')
    def test_samples_tenant_isolation(self, mock_get, mock_tpl):
        """Requests to downstream APIs include the caller's tenant ID."""
        from services.web.app import home
        from fastapi import Request

        auth = {"tenant_id": "tenant-a", "user_id": "user123", "role": "viewer"}

        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        mock_tpl.TemplateResponse.return_value = MagicMock()

        mock_request = MagicMock(spec=Request)
        asyncio.run(home(mock_request, auth, 20))

        call_headers = mock_get.call_args[1]["headers"]
        assert call_headers["X-Tenant-Id"] == "tenant-a"
