"""Thin HTTP client for Ollama's /api/chat endpoint."""

import requests


class OllamaUnavailableError(Exception):
    """Raised when Ollama cannot be reached."""


class OllamaTimeoutError(OllamaUnavailableError):
    """Raised when a request to Ollama times out."""


class OllamaClient:
    """Minimal client for Ollama's REST API."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "mistral:7b", timeout: int = 120) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def chat(self, messages: list[dict], temperature: float = 0.2) -> str:
        """
        Send a chat request and return the assistant's reply.

        Args:
            messages: List of {"role": ..., "content": ...} dicts.
            temperature: Sampling temperature (0.2 gives deterministic output).

        Returns:
            The model's text response.

        Raises:
            OllamaTimeoutError: If the request times out.
            OllamaUnavailableError: If Ollama is unreachable.
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        try:
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()["message"]["content"]
        except requests.exceptions.Timeout as exc:
            raise OllamaTimeoutError(f"Ollama request timed out after {self.timeout}s") from exc
        except requests.exceptions.ConnectionError as exc:
            raise OllamaUnavailableError(f"Cannot connect to Ollama at {self.base_url}") from exc
        except Exception as exc:
            raise OllamaUnavailableError(f"Ollama request failed: {exc}") from exc

    def is_available(self) -> bool:
        """
        Check whether Ollama is reachable by hitting /api/tags.

        Returns:
            True if reachable, False otherwise. Never raises.
        """
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception:
            return False
