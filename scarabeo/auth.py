"""Authentication and Authorization module for SCARABEO.

Supports two modes:
- header (default): X-Tenant-Id, X-User-Id, X-Role headers
- oidc (stub): JWT validation with JWKS
"""

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Any

logger = logging.getLogger(__name__)


class Role(str, Enum):
    """RBAC roles."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


class AuthMode(str, Enum):
    """Authentication modes."""

    HEADER = "header"
    OIDC = "oidc"


@dataclass(frozen=True)
class AuthContext:
    """Authentication context."""

    tenant_id: str
    user_id: str | None
    role: Role
    auth_mode: AuthMode
    ip_address: str | None
    user_agent: str | None

    def has_permission(self, required_role: Role) -> bool:
        """Check if user has required role or higher."""
        role_hierarchy = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMIN: 2}
        return role_hierarchy.get(self.role, -1) >= role_hierarchy.get(required_role, 999)


@dataclass
class AuthConfig:
    """Authentication configuration."""

    mode: AuthMode = AuthMode.HEADER
    oidc_jwks_url: str | None = None
    oidc_audience: str | None = None
    oidc_issuer: str | None = None
    oidc_jwks_cache_ttl: int = 3600

    # Header mode config
    header_tenant_header: str = "X-Tenant-Id"
    header_user_header: str = "X-User-Id"
    header_role_header: str = "X-Role"

    # Default role for header mode if not specified
    default_role: Role = Role.VIEWER


@lru_cache
def get_auth_config() -> AuthConfig:
    """Get cached auth configuration."""
    mode_str = os.environ.get("AUTH_MODE", "header").lower()
    mode = AuthMode.HEADER if mode_str == "header" else AuthMode.OIDC

    return AuthConfig(
        mode=mode,
        oidc_jwks_url=os.environ.get("OIDC_JWKS_URL"),
        oidc_audience=os.environ.get("OIDC_AUDIENCE"),
        oidc_issuer=os.environ.get("OIDC_ISSUER"),
        oidc_jwks_cache_ttl=int(os.environ.get("OIDC_JWKS_CACHE_TTL", "3600")),
    )


class AuthError(Exception):
    """Authentication error."""

    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class ForbiddenError(Exception):
    """Authorization error."""

    def __init__(self, message: str, status_code: int = 403):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def validate_tenant_id(tenant_id: str) -> bool:
    """Validate tenant ID format."""
    if not tenant_id or not tenant_id.strip():
        return False
    # Allow alphanumeric, hyphens, underscores
    import re
    return bool(re.match(r'^[a-zA-Z0-9_-]{1,255}$', tenant_id))


def validate_user_id(user_id: str | None) -> bool:
    """Validate user ID format."""
    if user_id is None:
        return True  # Optional
    if not user_id.strip():
        return False
    import re
    return bool(re.match(r'^[a-zA-Z0-9_-]{1,255}$', user_id))


def parse_role(role_str: str | None, default: Role = Role.VIEWER) -> Role:
    """Parse role string to Role enum."""
    if not role_str:
        return default
    try:
        return Role(role_str.lower())
    except ValueError:
        return default


def authenticate_from_headers(
    headers: dict[str, str],
    config: AuthConfig | None = None,
) -> AuthContext:
    """
    Authenticate from HTTP headers.

    Args:
        headers: Request headers (case-insensitive keys)
        config: Auth configuration

    Returns:
        AuthContext

    Raises:
        AuthError: If authentication fails
    """
    config = config or get_auth_config()

    # Normalize header keys to lowercase
    normalized_headers = {k.lower(): v for k, v in headers.items()}

    # Extract tenant ID
    tenant_id = normalized_headers.get(config.header_tenant_header.lower())
    if not tenant_id:
        raise AuthError(f"Missing required header: {config.header_tenant_header}", 400)

    if not validate_tenant_id(tenant_id):
        raise AuthError(f"Invalid tenant ID format: {tenant_id}", 400)

    # Extract user ID (optional)
    user_id = normalized_headers.get(config.header_user_header.lower())
    if user_id and not validate_user_id(user_id):
        raise AuthError(f"Invalid user ID format: {user_id}", 400)

    # Extract role
    role_str = normalized_headers.get(config.header_role_header.lower())
    role = parse_role(role_str, config.default_role)

    # Extract IP and user agent for audit
    ip_address = normalized_headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not ip_address:
        ip_address = normalized_headers.get("x-real-ip")
    user_agent = normalized_headers.get("user-agent")

    return AuthContext(
        tenant_id=tenant_id,
        user_id=user_id,
        role=role,
        auth_mode=AuthMode.HEADER,
        ip_address=ip_address,
        user_agent=user_agent,
    )


class JWKSFetcher:
    """Fetch and cache JWKS."""

    def __init__(self, jwks_url: str, cache_ttl: int = 3600):
        self.jwks_url = jwks_url
        self.cache_ttl = cache_ttl
        self._cache: dict[str, Any] = {}
        self._cache_time: float = 0

    def fetch(self) -> dict[str, Any]:
        """Fetch JWKS."""
        now = time.time()
        if self._cache and (now - self._cache_time) < self.cache_ttl:
            return self._cache

        # In production, this would fetch from JWKS URL
        # For now, return cached or empty
        if not self._cache:
            logger.warning(f"JWKS fetch not implemented for {self.jwks_url}")
            self._cache = {"keys": []}
            self._cache_time = now

        return self._cache


class OIDCAuthenticator:
    """OIDC JWT authentication (stub implementation)."""

    def __init__(self, config: AuthConfig):
        self.config = config
        self.jwks_fetcher = JWKSFetcher(
            config.oidc_jwks_url or "",
            config.oidc_jwks_cache_ttl,
        )

    def authenticate(self, token: str, headers: dict[str, str]) -> AuthContext:
        """
        Authenticate using OIDC JWT.

        Args:
            token: JWT token
            headers: Request headers

        Returns:
            AuthContext

        Raises:
            AuthError: If authentication fails
        """
        # Stub implementation - in production would:
        # 1. Fetch JWKS
        # 2. Verify JWT signature
        # 3. Verify audience and issuer
        # 4. Extract claims

        # For stub, decode JWT payload (no signature verification)
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise AuthError("Invalid JWT format", 401)

            # Decode payload
            import base64
            payload_b64 = parts[1]
            # Add padding if needed
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding

            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        except Exception as e:
            raise AuthError(f"Invalid JWT: {e}", 401) from e

        # Extract claims
        tenant_id = payload.get("tenant_id") or payload.get("tid")
        user_id = payload.get("user_id") or payload.get("sub")
        role_str = payload.get("role") or payload.get("roles", "")

        if isinstance(role_str, list):
            role_str = role_str[0] if role_str else ""

        if not tenant_id:
            raise AuthError("JWT missing tenant_id claim", 401)

        role = parse_role(role_str, Role.VIEWER)

        # Verify audience if configured
        if self.config.oidc_audience:
            aud = payload.get("aud", "")
            if isinstance(aud, list):
                aud = aud[0] if aud else ""
            if aud != self.config.oidc_audience:
                raise AuthError("JWT audience mismatch", 401)

        # Verify issuer if configured
        if self.config.oidc_issuer:
            iss = payload.get("iss", "")
            if iss != self.config.oidc_issuer:
                raise AuthError("JWT issuer mismatch", 401)

        # Extract IP and user agent
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        ip_address = normalized_headers.get("x-forwarded-for", "").split(",")[0].strip()
        if not ip_address:
            ip_address = normalized_headers.get("x-real-ip")
        user_agent = normalized_headers.get("user-agent")

        return AuthContext(
            tenant_id=tenant_id,
            user_id=user_id,
            role=role,
            auth_mode=AuthMode.OIDC,
            ip_address=ip_address,
            user_agent=user_agent,
        )


def authenticate(
    headers: dict[str, str],
    config: AuthConfig | None = None,
) -> AuthContext:
    """
    Authenticate request.

    Args:
        headers: Request headers
        config: Auth configuration

    Returns:
        AuthContext

    Raises:
        AuthError: If authentication fails
    """
    config = config or get_auth_config()

    if config.mode == AuthMode.HEADER:
        return authenticate_from_headers(headers, config)

    elif config.mode == AuthMode.OIDC:
        # Extract Bearer token
        auth_header = headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise AuthError("Missing or invalid Authorization header", 401)

        token = auth_header[7:]  # Remove "Bearer " prefix
        authenticator = OIDCAuthenticator(config)
        return authenticator.authenticate(token, headers)

    else:
        raise AuthError(f"Unknown auth mode: {config.mode}", 500)


def require_role(auth: AuthContext, required_role: Role) -> None:
    """
    Require specific role for authorization.

    Args:
        auth: AuthContext
        required_role: Required role

    Raises:
        ForbiddenError: If user doesn't have required role
    """
    if not auth.has_permission(required_role):
        raise ForbiddenError(
            f"Insufficient permissions. Required: {required_role.value}, Current: {auth.role.value}",
            403,
        )


# Convenience functions for FastAPI dependencies
def get_auth_from_headers(headers: dict) -> AuthContext:
    """FastAPI dependency for authentication."""
    return authenticate(headers)


def require_analyst(auth: AuthContext) -> AuthContext:
    """FastAPI dependency requiring analyst role."""
    require_role(auth, Role.ANALYST)
    return auth


def require_admin(auth: AuthContext) -> AuthContext:
    """FastAPI dependency requiring admin role."""
    require_role(auth, Role.ADMIN)
    return auth


def require_viewer(auth: AuthContext) -> AuthContext:
    """FastAPI dependency requiring viewer role (always passes if authenticated)."""
    require_role(auth, Role.VIEWER)
    return auth
