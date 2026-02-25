"""
Local AI explanation layer for normalized SCARABEO findings.

Distinct from scarabeo/ai.py (which returns free-text narrative):
this module enforces structured JSON output, validates it against a schema,
and exposes a provider abstraction so the backend can be swapped without
touching calling code.

Security guardrail: by default only localhost/127.0.0.1/::1 are accepted
as Ollama endpoints. Passing a remote URL raises LocalEndpointViolation
unless allow_remote=True is explicitly set on the provider.
"""

import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests
from jsonschema import Draft202012Validator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ExplanationError(Exception):
    """Base error for the explanation layer."""


class LocalEndpointViolation(ExplanationError):
    """
    Raised when a non-local endpoint is supplied to a provider.

    The explanation layer must not transmit findings to external services
    by default — findings may contain sensitive artefact details.
    """


class ExplanationParseError(ExplanationError):
    """
    Raised when the model response cannot be parsed into valid JSON
    or fails schema validation.
    """


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

EXPLANATION_JSON_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "behaviors", "confidence", "uncertainties", "evidence_refs"],
    "properties": {
        "summary": {
            "type": "string",
            "minLength": 1,
            "description": "1-3 sentence executive summary of what the sample does",
        },
        "behaviors": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Observable behaviours inferred from the findings",
        },
        "confidence": {
            "type": "integer",
            "minimum": 0,
            "maximum": 100,
            "description": "Analyst confidence in this explanation (0–100)",
        },
        "uncertainties": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Things that cannot be determined from the available evidence",
        },
        "evidence_refs": {
            "type": "array",
            "items": {"type": "string"},
            "description": "References to finding IDs / fields that support the conclusions",
        },
    },
}

_SCHEMA_VALIDATOR = Draft202012Validator(EXPLANATION_JSON_SCHEMA)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class ExplanationResult:
    """Structured AI explanation for a set of findings."""
    summary: str
    behaviors: list[str]
    confidence: int
    uncertainties: list[str]
    evidence_refs: list[str]
    model: str
    provider: str


# ---------------------------------------------------------------------------
# Security: local-endpoint guard
# ---------------------------------------------------------------------------

# urllib.parse returns the bare hostname (no brackets for IPv6)
_LOCAL_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})


def _assert_local_endpoint(url: str) -> None:
    """
    Raise LocalEndpointViolation if *url* does not resolve to a local address.

    This prevents findings from being inadvertently sent to a remote service.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host not in _LOCAL_HOSTS:
        raise LocalEndpointViolation(
            f"Non-local endpoint rejected: '{url}'. "
            f"The explanation layer only connects to localhost by default "
            f"(accepted hosts: {sorted(_LOCAL_HOSTS)}). "
            f"Set allow_remote=True on the provider to override."
        )


# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------

class ExplainerProvider(ABC):
    """
    Abstract interface for explanation backends.

    Concrete implementations must enforce locality guarantees appropriate
    to their transport layer.
    """

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Identifier for the model in use."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Short name for this provider (e.g. 'ollama')."""

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """
        Send *prompt* to the model and return the raw text response.

        Raises:
            ExplanationError: On any transport or provider-side failure.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the provider is reachable. Must never raise."""


# ---------------------------------------------------------------------------
# Ollama provider
# ---------------------------------------------------------------------------

class OllamaExplainerProvider(ExplainerProvider):
    """
    Explanation provider backed by a locally-running Ollama instance.

    Security guardrail: raises LocalEndpointViolation if *base_url* is not
    a loopback address, unless *allow_remote=True* is explicitly passed.
    Temperature is fixed at 0.0 to maximise determinism for JSON output.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "mistral:7b",
        timeout: int = 60,
        allow_remote: bool = False,
    ) -> None:
        if not allow_remote:
            _assert_local_endpoint(base_url)

        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def provider_name(self) -> str:
        return "ollama"

    def complete(self, prompt: str) -> str:
        """POST to /api/chat and return the assistant reply content."""
        payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {"temperature": 0.0},
        }
        try:
            resp = requests.post(
                f"{self._base_url}/api/chat",
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"]
        except requests.exceptions.Timeout as exc:
            raise ExplanationError(
                f"Ollama timed out after {self._timeout}s"
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            raise ExplanationError(
                f"Cannot connect to Ollama at {self._base_url}"
            ) from exc
        except Exception as exc:
            raise ExplanationError(f"Ollama request failed: {exc}") from exc

    def is_available(self) -> bool:
        try:
            resp = requests.get(f"{self._base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

_PROMPT_TEMPLATE = """\
You are a malware analysis assistant. Explain the following normalized security \
findings to a security analyst.

Findings (JSON):
{findings_json}

Respond ONLY with a single valid JSON object — no preamble, no trailing text, \
no markdown fences. The object must conform exactly to this structure:

{{
  "summary": "<1-3 sentence executive summary of what this sample does>",
  "behaviors": ["<observed behaviour 1>", "<observed behaviour 2>"],
  "confidence": <integer 0-100>,
  "uncertainties": ["<what cannot be determined from available evidence>"],
  "evidence_refs": ["<finding_id or finding_id:field that supports a conclusion>"]
}}

Rules:
- summary: non-empty string
- behaviors: list of strings (may be empty if no behaviours are clear)
- confidence: integer between 0 and 100 inclusive
- uncertainties: list of strings (may be empty)
- evidence_refs: list of strings referencing finding IDs
- Do not add any properties not listed above
- Do not wrap the JSON in markdown code fences
"""


def _build_prompt(findings: list[dict]) -> str:
    findings_json = json.dumps(findings, indent=2, default=str)
    return _PROMPT_TEMPLATE.format(findings_json=findings_json)


# ---------------------------------------------------------------------------
# JSON extraction and validation
# ---------------------------------------------------------------------------

_FENCED_BLOCK_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


def _extract_and_validate_json(text: str) -> dict:
    """
    Extract a JSON object from raw model output and validate it against
    EXPLANATION_JSON_SCHEMA.

    Tries candidates in priority order:
    1. First balanced ``{...}`` span
    2. Content of a fenced code block (``` or ```json)
    3. The full stripped text

    Raises:
        ExplanationParseError: If no valid, schema-conforming JSON is found.
    """
    candidates: list[str] = []

    # Highest priority: first balanced brace span
    brace_start = text.find("{")
    brace_end = text.rfind("}")
    if brace_start != -1 and brace_end > brace_start:
        candidates.append(text[brace_start : brace_end + 1])

    # Fenced code block
    m = _FENCED_BLOCK_RE.search(text)
    if m:
        candidates.append(m.group(1).strip())

    # Full text as fallback
    candidates.append(text.strip())

    last_error: Exception = ExplanationParseError(
        "No JSON content found in model response"
    )

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError as exc:
            last_error = ExplanationParseError(
                f"JSON decode error: {exc}"
            )
            continue

        schema_errors = list(_SCHEMA_VALIDATOR.iter_errors(parsed))
        if schema_errors:
            messages = "; ".join(e.message for e in schema_errors[:3])
            last_error = ExplanationParseError(
                f"Response failed schema validation: {messages}"
            )
            continue

        return parsed

    raise last_error


# ---------------------------------------------------------------------------
# Finding explainer
# ---------------------------------------------------------------------------

class FindingExplainer:
    """
    Orchestrates AI-powered explanation of normalized findings.

    Explanation is optional — ``explain()`` returns None and logs a warning
    on any failure so the calling pipeline is never blocked.
    Use ``explain_or_raise()`` when the caller wants to handle failure itself.
    """

    def __init__(self, provider: ExplainerProvider) -> None:
        self._provider = provider

    def explain(self, findings: list[dict]) -> Optional[ExplanationResult]:
        """
        Generate a structured explanation for *findings*.

        Returns:
            ExplanationResult on success, None on any failure.
        """
        if not findings:
            logger.debug("FindingExplainer: no findings to explain")
            return None

        prompt = _build_prompt(findings)

        try:
            raw = self._provider.complete(prompt)
        except ExplanationError as exc:
            logger.warning(f"Explanation provider error: {exc}")
            return None

        try:
            data = _extract_and_validate_json(raw)
        except ExplanationParseError as exc:
            logger.warning(f"Explanation parse/validation error: {exc}")
            return None

        return ExplanationResult(
            summary=data["summary"],
            behaviors=data["behaviors"],
            confidence=data["confidence"],
            uncertainties=data["uncertainties"],
            evidence_refs=data["evidence_refs"],
            model=self._provider.model_name,
            provider=self._provider.provider_name,
        )

    def explain_or_raise(self, findings: list[dict]) -> ExplanationResult:
        """
        Like ``explain()`` but raises on failure.

        Raises:
            ExplanationError: If the provider fails.
            ExplanationParseError: If JSON extraction/validation fails.
            ValueError: If findings is empty.
        """
        if not findings:
            raise ValueError("findings must be a non-empty list")

        prompt = _build_prompt(findings)
        raw = self._provider.complete(prompt)
        data = _extract_and_validate_json(raw)

        return ExplanationResult(
            summary=data["summary"],
            behaviors=data["behaviors"],
            confidence=data["confidence"],
            uncertainties=data["uncertainties"],
            evidence_refs=data["evidence_refs"],
            model=self._provider.model_name,
            provider=self._provider.provider_name,
        )
