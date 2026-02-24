"""SCARABEO CLI API client."""

import os
from typing import Any

import requests

# Re-export builtins for consumers that import them from this module
ConnectionError = ConnectionError


class ScarabeoClient:
    """HTTP client for SCARABEO API."""

    def __init__(
        self,
        base_url: str | None = None,
        tenant_id: str | None = None,
        user_id: str | None = None,
        role: str | None = None,
    ):
        """
        Initialize SCARABEO API client.

        Args:
            base_url: API base URL (default: SCARABEO_API_URL env)
            tenant_id: Tenant ID (default: SCARABEO_TENANT env)
            user_id: User ID (default: SCARABEO_USER env)
            role: User role (default: SCARABEO_ROLE env)
        """
        self.base_url = (base_url or os.environ.get("SCARABEO_API_URL", "http://localhost:8000")).rstrip("/")
        self.tenant_id = tenant_id or os.environ.get("SCARABEO_TENANT", "default")
        self.user_id = user_id or os.environ.get("SCARABEO_USER", "cli-user")
        self.role = role or os.environ.get("SCARABEO_ROLE", "analyst")

        self.session = requests.Session()
        self.session.headers.update({
            "X-Tenant-Id": self.tenant_id,
            "X-User-Id": self.user_id,
            "X-Role": self.role,
            "Content-Type": "application/json",
        })

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Make HTTP request with error handling."""
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(method, url, timeout=30, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Cannot connect to SCARABEO API at {url}: {e}") from e
        except requests.exceptions.Timeout as e:
            raise TimeoutError(f"Request timed out: {url}") from e
        except requests.exceptions.HTTPError as e:
            raise APIError(e.response.status_code, e.response.text) from e

    def health_check(self) -> dict:
        """Check service health."""
        response = self._request("GET", "/healthz")
        return response.json()

    def upload_sample(self, file_path: str, priority: str = "normal") -> dict:
        """
        Upload a sample for analysis.

        Args:
            file_path: Path to sample file
            priority: Analysis priority (low, normal, high, critical)

        Returns:
            Upload response with submission_id and sha256
        """
        with open(file_path, "rb") as f:
            response = self._request(
                "POST",
                "/samples",
                files={"file": f},
                data={"priority": priority},
            )
        return response.json()

    def get_sample(self, sha256: str) -> dict:
        """Get sample details."""
        return self._request("GET", f"/samples/{sha256}").json()

    def get_report(self, sha256: str) -> dict:
        """Get analysis report."""
        return self._request("GET", f"/samples/{sha256}/report").json()

    def list_samples(self, page: int = 1, per_page: int = 20) -> dict:
        """List samples with pagination."""
        return self._request(
            "GET",
            "/samples",
            params={"page": page, "per_page": per_page},
        ).json()

    def get_job(self, job_id: str) -> dict:
        """Get job details."""
        return self._request("GET", f"/jobs/{job_id}").json()

    def list_jobs(self, status: str | None = None) -> list[dict]:
        """List jobs, optionally filtered by status."""
        params = {}
        if status:
            params["status"] = status
        return self._request("GET", "/jobs", params=params).json()

    def retry_job(self, job_id: str) -> dict:
        """Retry a failed job (requires admin role)."""
        return self._request("POST", f"/jobs/{job_id}/retry").json()

    def search(self, query: str, page: int = 1, per_page: int = 20) -> dict:
        """Search samples."""
        return self._request(
            "GET",
            "/search",
            params={"q": query, "page": page, "per_page": per_page},
        ).json()

    def get_ioc_intel(self, ioc_value: str) -> dict:
        """Get IOC intelligence."""
        return self._request("GET", f"/intel/ioc/{ioc_value}").json()

    def list_cases(self) -> list[dict]:
        """List cases."""
        return self._request("GET", "/cases").json()

    def create_case(self, name: str, description: str | None = None) -> dict:
        """Create a new case."""
        data = {"name": name}
        if description:
            data["description"] = description
        return self._request("POST", "/cases", json=data).json()

    def add_sample_to_case(self, case_id: str, sha256: str, notes: str | None = None) -> dict:
        """Add sample to case."""
        data = {"sample_sha256": sha256}
        if notes:
            data["notes"] = notes
        return self._request("POST", f"/cases/{case_id}/samples", json=data).json()


class APIError(Exception):
    """API error with status code."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"API Error {status_code}: {message}")


def get_client() -> ScarabeoClient:
    """Get configured API client."""
    return ScarabeoClient()
