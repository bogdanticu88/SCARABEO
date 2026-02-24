"""Scarabeo Analysis Framework."""

from scarabeo.banner import show_banner, get_banner_text
from scarabeo.version import get_version, get_version_info, __version__
from scarabeo.auth import AuthContext, Role, AuthMode, authenticate, require_role
from scarabeo.logging import setup_logging, get_context_logger
from scarabeo.metrics import get_metrics_collector, init_metrics
from scarabeo.rate_limit import get_rate_limiter, get_quota_enforcer

__all__ = [
    "show_banner",
    "get_banner_text",
    "get_version",
    "get_version_info",
    "__version__",
    "AuthContext",
    "Role",
    "AuthMode",
    "authenticate",
    "require_role",
    "setup_logging",
    "get_context_logger",
    "get_metrics_collector",
    "init_metrics",
    "get_rate_limiter",
    "get_quota_enforcer",
]
