"""Structured logging for SCARABEO services."""

import json
import logging
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Any


class StructuredFormatter(logging.Formatter):
    """JSON structured log formatter."""

    def __init__(
        self,
        service_name: str | None = None,
        include_extra: bool = True,
    ):
        super().__init__()
        self.service_name = service_name or os.environ.get("SERVICE_NAME", "unknown")
        self.include_extra = include_extra

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
        }

        # Add location info
        if record.filename:
            log_entry["location"] = {
                "file": record.filename,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info),
            }

        # Add extra fields from record
        if self.include_extra:
            extra_fields = {
                "tenant_id": getattr(record, "tenant_id", None),
                "user_id": getattr(record, "user_id", None),
                "request_id": getattr(record, "request_id", None),
                "job_id": getattr(record, "job_id", None),
                "sample_sha256": getattr(record, "sample_sha256", None),
                "event": getattr(record, "event", None),
                "severity": getattr(record, "severity", record.levelname),
            }
            # Only include non-None extra fields
            for key, value in extra_fields.items():
                if value is not None:
                    log_entry[key] = value

        return json.dumps(log_entry, default=str)


def setup_logging(
    service_name: str,
    level: str | None = None,
    json_format: bool = True,
) -> None:
    """
    Setup structured logging for a service.

    Args:
        service_name: Name of the service
        level: Log level (default from env LOG_LEVEL)
        json_format: Use JSON format (default True)
    """
    level_str = level or os.environ.get("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, level_str, logging.INFO)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers
    root_logger.handlers = []

    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)

    if json_format:
        handler.setFormatter(StructuredFormatter(service_name=service_name))
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))

    root_logger.addHandler(handler)

    # Reduce noise from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get logger with service name prefix."""
    service = os.environ.get("SERVICE_NAME", "unknown")
    return logging.getLogger(f"{service}.{name}")


class LogContext:
    """Context manager for adding log context."""

    def __init__(self, **kwargs: Any):
        self.context = kwargs
        self.old_context: dict[str, Any] = {}

    def __enter__(self) -> "LogContext":
        # Store old context
        self.old_context = getattr(_log_context_var, "context", {})
        # Set new context
        _log_context_var.context = {**self.old_context, **self.context}
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        # Restore old context
        _log_context_var.context = self.old_context


# Thread-local context storage
class _LogContextVar:
    context: dict[str, Any] = {}


_log_context_var = _LogContextVar()


def add_log_context(**kwargs: Any) -> None:
    """Add context to current log context."""
    _log_context_var.context.update(kwargs)


def clear_log_context() -> None:
    """Clear current log context."""
    _log_context_var.context = {}


def get_log_context() -> dict[str, Any]:
    """Get current log context."""
    return _log_context_var.context.copy()


class ContextAdapter(logging.LoggerAdapter):
    """Logger adapter that adds context."""

    def process(self, msg: str, kwargs: dict) -> tuple[str, dict]:
        """Add context to log record."""
        extra = kwargs.get("extra", {})
        extra.update(get_log_context())
        kwargs["extra"] = extra
        return msg, kwargs


def get_context_logger(name: str) -> ContextAdapter:
    """Get logger with context support."""
    logger = logging.getLogger(name)
    return ContextAdapter(logger, get_log_context())
