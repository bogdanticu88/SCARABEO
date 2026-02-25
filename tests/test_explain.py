"""
Unit tests for scarabeo/explain.py — local AI explanation layer.

All Ollama calls are mocked; no running Ollama instance is required.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from jsonschema import Draft202012Validator

from scarabeo.explain import (
    EXPLANATION_JSON_SCHEMA,
    ExplanationError,
    ExplanationParseError,
    ExplanationResult,
    FindingExplainer,
    LocalEndpointViolation,
    OllamaExplainerProvider,
    _assert_local_endpoint,
    _build_prompt,
    _extract_and_validate_json,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _valid_explanation() -> dict:
    return {
        "summary": "This sample performs process injection and phones home.",
        "behaviors": ["process injection", "C2 communication"],
        "confidence": 85,
        "uncertainties": ["exact payload is encrypted"],
        "evidence_refs": ["f-001:title", "f-002:description"],
    }


def _valid_findings() -> list[dict]:
    return [
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
            "title": "Network Beacon",
            "severity": "MEDIUM",
            "confidence": 75,
            "description": "Periodic outbound connection to 192.0.2.1:443",
            "evidence": [],
            "source": "pe-analyzer",
            "created_at": "2024-01-15T10:00:00Z",
        },
    ]


def _provider_returning(response_dict: dict) -> OllamaExplainerProvider:
    """Return a provider whose complete() returns *response_dict* as JSON."""
    provider = OllamaExplainerProvider.__new__(OllamaExplainerProvider)
    provider._base_url = "http://localhost:11434"
    provider._model = "mistral:7b"
    provider._timeout = 60
    provider.complete = MagicMock(return_value=json.dumps(response_dict))
    provider.is_available = MagicMock(return_value=True)
    return provider


# ---------------------------------------------------------------------------
# TestLocalEndpointGuardrail
# ---------------------------------------------------------------------------

class TestLocalEndpointGuardrail:

    def test_localhost_accepted(self):
        """http://localhost should pass the guardrail."""
        _assert_local_endpoint("http://localhost:11434")  # must not raise

    def test_127_0_0_1_accepted(self):
        """http://127.0.0.1 should pass the guardrail."""
        _assert_local_endpoint("http://127.0.0.1:11434")  # must not raise

    def test_ipv6_loopback_accepted(self):
        """http://[::1] should pass the guardrail."""
        _assert_local_endpoint("http://[::1]:11434")  # must not raise

    def test_remote_host_rejected(self):
        """A public hostname must raise LocalEndpointViolation by default."""
        with pytest.raises(LocalEndpointViolation):
            _assert_local_endpoint("http://remote-ollama.example.com:11434")

    def test_private_ip_rejected(self):
        """10.x.x.x is not a loopback address and must be rejected."""
        with pytest.raises(LocalEndpointViolation):
            _assert_local_endpoint("http://10.0.0.1:11434")

    def test_provider_rejects_remote_url_by_default(self):
        """OllamaExplainerProvider must raise on construction with a remote URL."""
        with pytest.raises(LocalEndpointViolation):
            OllamaExplainerProvider(base_url="https://api.external.ai/ollama")

    def test_allow_remote_bypasses_guardrail(self):
        """allow_remote=True suppresses the locality check."""
        # Should not raise
        provider = OllamaExplainerProvider(
            base_url="http://10.0.0.1:11434",
            allow_remote=True,
        )
        assert provider.provider_name == "ollama"

    def test_error_message_includes_url(self):
        """The violation error message must include the rejected URL."""
        url = "http://remote.example.com:11434"
        with pytest.raises(LocalEndpointViolation) as exc_info:
            _assert_local_endpoint(url)
        assert "remote.example.com" in str(exc_info.value)


# ---------------------------------------------------------------------------
# TestOllamaExplainerProvider
# ---------------------------------------------------------------------------

class TestOllamaExplainerProvider:

    def test_provider_name_is_ollama(self):
        provider = OllamaExplainerProvider()
        assert provider.provider_name == "ollama"

    def test_model_name_reflects_constructor(self):
        provider = OllamaExplainerProvider(model="llama3:8b")
        assert provider.model_name == "llama3:8b"

    def test_complete_returns_content_string(self):
        """complete() extracts the message content from Ollama's JSON response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"message": {"content": '{"summary":"test"}'}}
        mock_response.raise_for_status = MagicMock()

        with patch("scarabeo.explain.requests.post", return_value=mock_response):
            provider = OllamaExplainerProvider()
            result = provider.complete("some prompt")

        assert result == '{"summary":"test"}'

    def test_complete_uses_zero_temperature(self):
        """complete() must set temperature=0.0 for deterministic output."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"message": {"content": "{}"}}
        mock_response.raise_for_status = MagicMock()

        with patch("scarabeo.explain.requests.post", return_value=mock_response) as mock_post:
            OllamaExplainerProvider().complete("prompt")

        payload = mock_post.call_args[1]["json"]
        assert payload["options"]["temperature"] == 0.0

    def test_is_available_true_on_200(self):
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("scarabeo.explain.requests.get", return_value=mock_response):
            assert OllamaExplainerProvider().is_available() is True

    def test_is_available_false_on_connection_error(self):
        import requests as req
        with patch("scarabeo.explain.requests.get", side_effect=req.exceptions.ConnectionError):
            assert OllamaExplainerProvider().is_available() is False

    def test_complete_raises_explanation_error_on_timeout(self):
        import requests as req
        with patch("scarabeo.explain.requests.post", side_effect=req.exceptions.Timeout):
            with pytest.raises(ExplanationError):
                OllamaExplainerProvider().complete("prompt")

    def test_complete_raises_explanation_error_on_connection_error(self):
        import requests as req
        with patch("scarabeo.explain.requests.post", side_effect=req.exceptions.ConnectionError):
            with pytest.raises(ExplanationError):
                OllamaExplainerProvider().complete("prompt")


# ---------------------------------------------------------------------------
# TestJsonExtraction
# ---------------------------------------------------------------------------

class TestJsonExtraction:

    def test_clean_json_string_parsed(self):
        text = json.dumps(_valid_explanation())
        result = _extract_and_validate_json(text)
        assert result["confidence"] == 85

    def test_json_with_surrounding_noise_extracted(self):
        """The brace-span extractor must strip preamble/postamble text."""
        text = "Here is the explanation:\n" + json.dumps(_valid_explanation()) + "\nDone."
        result = _extract_and_validate_json(text)
        assert result["summary"] == _valid_explanation()["summary"]

    def test_fenced_code_block_extracted(self):
        inner = json.dumps(_valid_explanation())
        text = f"```json\n{inner}\n```"
        result = _extract_and_validate_json(text)
        assert result["behaviors"] == _valid_explanation()["behaviors"]

    def test_invalid_json_raises_parse_error(self):
        with pytest.raises(ExplanationParseError):
            _extract_and_validate_json("not json at all")

    def test_valid_json_wrong_schema_raises_parse_error(self):
        """JSON that parses but violates the schema must raise ExplanationParseError."""
        bad = {"summary": "ok", "behaviors": [], "confidence": 200}  # confidence > 100
        with pytest.raises(ExplanationParseError):
            _extract_and_validate_json(json.dumps(bad))

    def test_missing_required_field_raises_parse_error(self):
        incomplete = {k: v for k, v in _valid_explanation().items() if k != "uncertainties"}
        with pytest.raises(ExplanationParseError):
            _extract_and_validate_json(json.dumps(incomplete))

    def test_extra_properties_rejected(self):
        """additionalProperties: false — extra keys must fail validation."""
        extra = {**_valid_explanation(), "attacker_group": "APT99"}
        with pytest.raises(ExplanationParseError):
            _extract_and_validate_json(json.dumps(extra))


# ---------------------------------------------------------------------------
# TestPromptBuilding
# ---------------------------------------------------------------------------

class TestPromptBuilding:

    def test_prompt_contains_finding_id(self):
        prompt = _build_prompt(_valid_findings())
        assert "f-001" in prompt

    def test_prompt_contains_finding_title(self):
        prompt = _build_prompt(_valid_findings())
        assert "Suspicious Import" in prompt

    def test_prompt_instructs_json_only_output(self):
        prompt = _build_prompt(_valid_findings())
        assert "JSON" in prompt

    def test_prompt_includes_required_fields_in_template(self):
        prompt = _build_prompt(_valid_findings())
        for field in ("summary", "behaviors", "confidence", "uncertainties", "evidence_refs"):
            assert field in prompt


# ---------------------------------------------------------------------------
# TestFindingExplainer
# ---------------------------------------------------------------------------

class TestFindingExplainer:

    def test_explain_happy_path_returns_result(self):
        provider = _provider_returning(_valid_explanation())
        explainer = FindingExplainer(provider)
        result = explainer.explain(_valid_findings())

        assert isinstance(result, ExplanationResult)
        assert result.summary == _valid_explanation()["summary"]
        assert result.confidence == 85
        assert result.provider == "ollama"
        assert result.model == "mistral:7b"

    def test_explain_empty_findings_returns_none(self):
        provider = _provider_returning(_valid_explanation())
        explainer = FindingExplainer(provider)
        assert explainer.explain([]) is None

    def test_explain_returns_none_on_provider_error(self):
        provider = OllamaExplainerProvider.__new__(OllamaExplainerProvider)
        provider._base_url = "http://localhost:11434"
        provider._model = "mistral:7b"
        provider._timeout = 60
        provider.complete = MagicMock(side_effect=ExplanationError("connection refused"))

        explainer = FindingExplainer(provider)
        result = explainer.explain(_valid_findings())
        assert result is None

    def test_explain_returns_none_on_parse_error(self):
        provider = OllamaExplainerProvider.__new__(OllamaExplainerProvider)
        provider._base_url = "http://localhost:11434"
        provider._model = "mistral:7b"
        provider._timeout = 60
        provider.complete = MagicMock(return_value="I cannot provide JSON right now.")

        explainer = FindingExplainer(provider)
        result = explainer.explain(_valid_findings())
        assert result is None

    def test_explain_returns_none_on_schema_violation(self):
        """Model returns parseable JSON but it fails schema validation."""
        bad_response = {"summary": "ok", "behaviors": "not-a-list"}
        provider = _provider_returning(bad_response)
        explainer = FindingExplainer(provider)
        assert explainer.explain(_valid_findings()) is None

    def test_explain_result_has_all_fields(self):
        provider = _provider_returning(_valid_explanation())
        result = FindingExplainer(provider).explain(_valid_findings())

        assert result is not None
        assert isinstance(result.behaviors, list)
        assert isinstance(result.uncertainties, list)
        assert isinstance(result.evidence_refs, list)
        assert 0 <= result.confidence <= 100

    def test_explain_or_raise_happy_path(self):
        provider = _provider_returning(_valid_explanation())
        result = FindingExplainer(provider).explain_or_raise(_valid_findings())
        assert result.confidence == 85

    def test_explain_or_raise_raises_on_empty_findings(self):
        provider = _provider_returning(_valid_explanation())
        with pytest.raises(ValueError):
            FindingExplainer(provider).explain_or_raise([])

    def test_explain_or_raise_propagates_provider_error(self):
        provider = OllamaExplainerProvider.__new__(OllamaExplainerProvider)
        provider._base_url = "http://localhost:11434"
        provider._model = "mistral:7b"
        provider._timeout = 60
        provider.complete = MagicMock(side_effect=ExplanationError("down"))

        with pytest.raises(ExplanationError):
            FindingExplainer(provider).explain_or_raise(_valid_findings())


# ---------------------------------------------------------------------------
# TestExplanationSchema
# ---------------------------------------------------------------------------

class TestExplanationSchema:

    _validator = Draft202012Validator(EXPLANATION_JSON_SCHEMA)

    def test_valid_explanation_passes(self):
        errors = list(self._validator.iter_errors(_valid_explanation()))
        assert errors == []

    def test_missing_summary_fails(self):
        data = {k: v for k, v in _valid_explanation().items() if k != "summary"}
        errors = list(self._validator.iter_errors(data))
        assert any("summary" in e.message for e in errors)

    def test_confidence_above_100_fails(self):
        data = {**_valid_explanation(), "confidence": 101}
        errors = list(self._validator.iter_errors(data))
        assert errors

    def test_confidence_below_0_fails(self):
        data = {**_valid_explanation(), "confidence": -1}
        errors = list(self._validator.iter_errors(data))
        assert errors

    def test_behaviors_not_array_fails(self):
        data = {**_valid_explanation(), "behaviors": "process injection"}
        errors = list(self._validator.iter_errors(data))
        assert errors

    def test_additional_property_fails(self):
        data = {**_valid_explanation(), "attacker": "APT99"}
        errors = list(self._validator.iter_errors(data))
        assert errors

    def test_empty_behaviors_and_uncertainties_valid(self):
        """Arrays may be empty."""
        data = {**_valid_explanation(), "behaviors": [], "uncertainties": []}
        errors = list(self._validator.iter_errors(data))
        assert errors == []
