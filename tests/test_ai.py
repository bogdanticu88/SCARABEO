"""Unit tests for scarabeo.llm and scarabeo.ai (all mocked — no Ollama required)."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

from scarabeo.llm import OllamaClient, OllamaTimeoutError, OllamaUnavailableError
from scarabeo.ai import (
    enrich_report_with_ai,
    explain_finding,
    generate_report_narrative,
    suggest_remediation,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

SHA256 = "a" * 64


def _make_client(response_text: str = "mocked response") -> OllamaClient:
    """Return an OllamaClient whose .chat() always returns *response_text*."""
    client = OllamaClient(base_url="http://localhost:11434", model="mistral:7b")
    client.chat = MagicMock(return_value=response_text)
    return client


def _sample_report() -> dict:
    return {
        "schema_version": "1.0.0",
        "sample_sha256": SHA256,
        "tenant_id": "tenant-123",
        "file_type": "PE32 executable",
        "summary": {"verdict": "malicious", "score": 87},
        "findings": [
            {
                "id": "f-001",
                "title": "Suspicious Import",
                "severity": "HIGH",
                "confidence": 90,
                "description": "Imports VirtualAllocEx used for process injection",
                "evidence": [{"type": "import", "value": "VirtualAllocEx"}],
                "source": "pe-analyzer",
                "created_at": "2024-01-15T10:00:00Z",
            },
            {
                "id": "f-002",
                "title": "Packed Binary",
                "severity": "MEDIUM",
                "confidence": 75,
                "description": "High entropy section suggests packing",
                "evidence": [],
                "source": "pe-analyzer",
                "created_at": "2024-01-15T10:00:00Z",
            },
        ],
        "iocs": [
            {"type": "ip", "value": "192.0.2.1", "normalized": "192.0.2.1", "confidence": 80, "first_seen_in": "pe-analyzer"},
            {"type": "domain", "value": "evil.example.com", "normalized": "evil.example.com", "confidence": 90, "first_seen_in": "pe-analyzer"},
        ],
        "artifacts": [],
        "provenance": {
            "pipeline_name": "standard",
            "pipeline_hash": "b" * 64,
            "engines": [{"name": "pe-analyzer", "version": "0.1.0"}],
            "config_hash": "c" * 64,
            "deterministic_run": True,
        },
        "timestamps": {
            "analysis_start": "2024-01-15T10:00:00Z",
            "analysis_end": "2024-01-15T10:05:00Z",
        },
    }


def _sample_finding() -> dict:
    return {
        "id": "f-001",
        "title": "Suspicious Import",
        "severity": "HIGH",
        "confidence": 90,
        "description": "Imports VirtualAllocEx used for process injection",
        "evidence": [{"type": "import", "value": "VirtualAllocEx"}],
        "source": "pe-analyzer",
        "created_at": "2024-01-15T10:00:00Z",
    }


# ---------------------------------------------------------------------------
# TestOllamaClient
# ---------------------------------------------------------------------------

class TestOllamaClient:

    def test_chat_returns_string(self):
        """chat() extracts the content string from the Ollama JSON response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"message": {"content": "hello world"}}
        mock_response.raise_for_status = MagicMock()

        with patch("scarabeo.llm.requests.post", return_value=mock_response):
            client = OllamaClient()
            result = client.chat([{"role": "user", "content": "hi"}])

        assert result == "hello world"

    def test_is_available_true(self):
        """is_available() returns True when Ollama responds with 200."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("scarabeo.llm.requests.get", return_value=mock_response):
            client = OllamaClient()
            assert client.is_available() is True

    def test_is_available_false_on_connection_error(self):
        """is_available() returns False when Ollama is unreachable."""
        with patch("scarabeo.llm.requests.get", side_effect=requests.exceptions.ConnectionError):
            client = OllamaClient()
            assert client.is_available() is False

    def test_timeout_raises_ollama_timeout_error(self):
        """chat() raises OllamaTimeoutError when the request times out."""
        with patch("scarabeo.llm.requests.post", side_effect=requests.exceptions.Timeout):
            client = OllamaClient()
            with pytest.raises(OllamaTimeoutError):
                client.chat([{"role": "user", "content": "hi"}])

    def test_connection_error_raises_ollama_unavailable_error(self):
        """chat() raises OllamaUnavailableError on connection failure."""
        with patch("scarabeo.llm.requests.post", side_effect=requests.exceptions.ConnectionError):
            client = OllamaClient()
            with pytest.raises(OllamaUnavailableError):
                client.chat([{"role": "user", "content": "hi"}])


# ---------------------------------------------------------------------------
# TestPromptBuilding — verify prompt content without network calls
# ---------------------------------------------------------------------------

class TestPromptBuilding:

    def test_narrative_prompt_includes_verdict(self):
        """generate_report_narrative sends a prompt that contains the verdict."""
        client = _make_client("narrative text")
        generate_report_narrative(_sample_report(), client)

        call_args = client.chat.call_args
        messages = call_args[0][0]
        combined = " ".join(m["content"] for m in messages)
        assert "malicious" in combined

    def test_explain_prompt_includes_severity(self):
        """explain_finding sends a prompt that contains the finding severity."""
        client = _make_client("explanation text")
        explain_finding(_sample_finding(), client)

        call_args = client.chat.call_args
        messages = call_args[0][0]
        combined = " ".join(m["content"] for m in messages)
        assert "HIGH" in combined

    def test_remediation_prompt_includes_iocs(self):
        """suggest_remediation sends a prompt that includes IOC values."""
        client = _make_client("remediation text")
        suggest_remediation(_sample_report(), client)

        call_args = client.chat.call_args
        messages = call_args[0][0]
        combined = " ".join(m["content"] for m in messages)
        assert "192.0.2.1" in combined

    def test_remediation_prompt_includes_all_findings(self):
        """suggest_remediation includes all finding titles in the prompt."""
        client = _make_client("remediation text")
        suggest_remediation(_sample_report(), client)

        call_args = client.chat.call_args
        messages = call_args[0][0]
        combined = " ".join(m["content"] for m in messages)
        assert "Suspicious Import" in combined
        assert "Packed Binary" in combined


# ---------------------------------------------------------------------------
# TestEnrichReportWithAI
# ---------------------------------------------------------------------------

class TestEnrichReportWithAI:

    def test_enrich_adds_ai_analysis_key(self):
        """enrich_report_with_ai returns a dict (not None)."""
        client = _make_client("some AI output")
        result = enrich_report_with_ai(_sample_report(), client)
        assert isinstance(result, dict)

    def test_enrich_returns_narrative_and_remediation(self):
        """Result contains both narrative and remediation keys."""
        client = _make_client("some AI output")
        result = enrich_report_with_ai(_sample_report(), client)
        assert "narrative" in result
        assert "remediation" in result
        assert result["narrative"] == "some AI output"
        assert result["remediation"] == "some AI output"

    def test_enrich_records_model_name(self):
        """Result contains the model name from the client."""
        client = _make_client()
        client.model = "mistral:7b"
        result = enrich_report_with_ai(_sample_report(), client)
        assert result["model"] == "mistral:7b"

    def test_enrich_records_generated_at_timestamp(self):
        """Result contains a generated_at ISO8601 timestamp."""
        client = _make_client()
        result = enrich_report_with_ai(_sample_report(), client)
        assert "generated_at" in result
        # Must be parseable as ISO8601
        dt = datetime.fromisoformat(result["generated_at"])
        assert dt.tzinfo is not None


# ---------------------------------------------------------------------------
# TestWorkerFailSafe
# ---------------------------------------------------------------------------

class TestWorkerFailSafe:

    def test_ollama_unavailable_does_not_fail_job(self):
        """
        When OllamaUnavailableError is raised, the caller's try/except must
        suppress it — no ai_analysis key should be set.
        """
        report_data = _sample_report()

        # Simulate what processor.py does
        try:
            client = OllamaClient()
            client.chat = MagicMock(side_effect=OllamaUnavailableError("down"))
            report_data["ai_analysis"] = enrich_report_with_ai(report_data, client)
        except Exception:
            pass  # fail-open

        assert "ai_analysis" not in report_data

    def test_enrich_result_matches_schema(self):
        """enrich_report_with_ai result has exactly the four expected keys."""
        client = _make_client("output text")
        result = enrich_report_with_ai(_sample_report(), client)
        assert set(result.keys()) == {"narrative", "remediation", "generated_at", "model"}
