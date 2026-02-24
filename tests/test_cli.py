"""Tests for SCARABEO CLI."""

import io
import pytest
from unittest.mock import MagicMock, patch, mock_open


class TestCLIClient:
    """Tests for CLI API client."""

    @patch('services.cli.client.requests.Session')
    def test_client_initialization(self, mock_session):
        """Test client initializes with correct defaults."""
        from services.cli.client import ScarabeoClient

        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "ok"}
        mock_session.return_value.request.return_value = mock_response

        client = ScarabeoClient(
            base_url="http://test:8000",
            tenant_id="test-tenant",
            user_id="test-user",
            role="analyst",
        )

        assert client.base_url == "http://test:8000"
        assert client.tenant_id == "test-tenant"
        assert client.user_id == "test-user"
        assert client.role == "analyst"

    @patch('services.cli.client.requests.Session')
    def test_client_default_env(self, mock_session):
        """Test client uses environment defaults."""
        from services.cli.client import ScarabeoClient

        client = ScarabeoClient()

        assert client.base_url == "http://localhost:8000"
        assert client.tenant_id == "default"

    @patch('services.cli.client.requests.Session')
    def test_health_check(self, mock_session):
        """Test health check request."""
        from services.cli.client import ScarabeoClient

        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "healthy"}
        mock_session.return_value.request.return_value = mock_response

        client = ScarabeoClient()
        result = client.health_check()

        assert result == {"status": "healthy"}
        mock_session.return_value.request.assert_called_once_with(
            "GET", "http://localhost:8000/healthz", timeout=30
        )

    @patch('services.cli.client.requests.Session')
    def test_upload_sample(self, mock_session):
        """Test sample upload."""
        from services.cli.client import ScarabeoClient

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "submission_id": "123",
            "sha256": "abc123",
            "status": "queued",
        }
        mock_session.return_value.request.return_value = mock_response

        client = ScarabeoClient()

        with patch("builtins.open", mock_open(read_data=b"test data")):
            result = client.upload_sample("/path/to/file.exe")

        assert result["submission_id"] == "123"
        assert result["sha256"] == "abc123"

    @patch('services.cli.client.requests.Session')
    def test_get_sample(self, mock_session):
        """Test getting sample details."""
        from services.cli.client import ScarabeoClient

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "sha256": "abc123",
            "filename": "test.exe",
            "size_bytes": 1024,
        }
        mock_session.return_value.request.return_value = mock_response

        client = ScarabeoClient()
        result = client.get_sample("abc123")

        assert result["sha256"] == "abc123"
        mock_session.return_value.request.assert_called_once_with(
            "GET", "http://localhost:8000/samples/abc123", timeout=30
        )

    @patch('services.cli.client.requests.Session')
    def test_connection_error(self, mock_session):
        """Test connection error handling."""
        from services.cli.client import ScarabeoClient, ConnectionError

        mock_session.return_value.request.side_effect = ConnectionError()

        client = ScarabeoClient()

        with pytest.raises(ConnectionError):
            client.health_check()

    @patch('services.cli.client.requests.Session')
    def test_api_error(self, mock_session):
        """Test API error handling."""
        from services.cli.client import ScarabeoClient, APIError
        from requests.exceptions import HTTPError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Not found"
        http_error = HTTPError(response=mock_response)
        mock_session.return_value.request.side_effect = http_error

        client = ScarabeoClient()

        with pytest.raises(APIError) as exc_info:
            client.health_check()

        assert exc_info.value.status_code == 404


class TestCLIConsole:
    """Tests for CLI console."""

    @patch('services.cli.console.ScarabeoClient')
    def test_console_initialization(self, mock_client):
        """Test console initializes correctly."""
        from services.cli.console import Console

        console = Console()

        assert console.running is True
        assert console.prompt == "scarabeo > "

    @patch('services.cli.console.ScarabeoClient')
    def test_process_help_command(self, mock_client):
        """Test help command."""
        from services.cli.console import Console

        console = Console()

        # Should not raise and should return True to continue
        result = console.process_command("help")
        assert result is True
        assert console.running is True

    @patch('services.cli.console.ScarabeoClient')
    def test_process_version_command(self, mock_client):
        """Test version command."""
        from services.cli.console import Console

        console = Console()
        result = console.process_command("version")
        assert result is True

    @patch('services.cli.console.ScarabeoClient')
    def test_process_exit_command(self, mock_client):
        """Test exit command."""
        from services.cli.console import Console

        console = Console()
        result = console.process_command("exit")
        assert result is False
        assert console.running is False

    @patch('services.cli.console.ScarabeoClient')
    def test_process_unknown_command(self, mock_client):
        """Test unknown command."""
        from services.cli.console import Console

        console = Console()
        result = console.process_command("unknown_command")
        assert result is True

    @patch('services.cli.console.ScarabeoClient')
    def test_process_empty_command(self, mock_client):
        """Test empty command."""
        from services.cli.console import Console

        console = Console()
        result = console.process_command("")
        assert result is True

    @patch('services.cli.console.ScarabeoClient')
    def test_process_upload_no_args(self, mock_client):
        """Test upload command without arguments."""
        from services.cli.console import Console

        console = Console()
        result = console.process_command("upload")
        assert result is True

    @patch('services.cli.console.ScarabeoClient')
    def test_process_status_no_args(self, mock_client):
        """Test status command without arguments."""
        from services.cli.console import Console

        console = Console()
        result = console.process_command("status")
        assert result is True

    @patch('services.cli.console.ScarabeoClient')
    def test_process_report_no_args(self, mock_client):
        """Test report command without arguments."""
        from services.cli.console import Console

        console = Console()
        result = console.process_command("report")
        assert result is True


class TestCLIIntegration:
    """Integration tests for CLI."""

    @patch('services.cli.client.requests.Session')
    def test_full_upload_workflow(self, mock_session):
        """Test full upload workflow."""
        from services.cli.client import ScarabeoClient

        # Mock upload response
        upload_response = MagicMock()
        upload_response.json.return_value = {
            "submission_id": "test-id",
            "sha256": "a" * 64,
            "status": "queued",
        }

        # Mock status response
        status_response = MagicMock()
        status_response.json.return_value = {
            "sha256": "a" * 64,
            "filename": "test.exe",
            "status": "queued",
        }

        mock_session.return_value.request.side_effect = [
            upload_response,
            status_response,
        ]

        client = ScarabeoClient()

        # Upload
        with patch("builtins.open", mock_open(read_data=b"test")):
            upload_result = client.upload_sample("/test.exe")

        # Check status
        status_result = client.get_sample("a" * 64)

        assert upload_result["sha256"] == "a" * 64
        assert status_result["sha256"] == "a" * 64
