"""Unit tests for enterprise hardening features."""

import json
import time
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta


class TestAuthModule:
    """Tests for authentication module."""

    def test_validate_tenant_id_valid(self):
        """Test valid tenant ID validation."""
        from scarabeo.auth import validate_tenant_id
        
        assert validate_tenant_id("tenant-123") is True
        assert validate_tenant_id("my_tenant") is True
        assert validate_tenant_id("Tenant1") is True

    def test_validate_tenant_id_invalid(self):
        """Test invalid tenant ID validation."""
        from scarabeo.auth import validate_tenant_id
        
        assert validate_tenant_id("") is False
        assert validate_tenant_id("   ") is False
        assert validate_tenant_id("tenant@123") is False
        assert validate_tenant_id("a" * 256) is False

    def test_parse_role_valid(self):
        """Test role parsing."""
        from scarabeo.auth import parse_role, Role
        
        assert parse_role("viewer") == Role.VIEWER
        assert parse_role("analyst") == Role.ANALYST
        assert parse_role("admin") == Role.ADMIN
        assert parse_role("ADMIN") == Role.ADMIN

    def test_parse_role_default(self):
        """Test default role on invalid input."""
        from scarabeo.auth import parse_role, Role
        
        assert parse_role(None) == Role.VIEWER
        assert parse_role("") == Role.VIEWER
        assert parse_role("invalid") == Role.VIEWER

    def test_auth_context_has_permission(self):
        """Test role hierarchy."""
        from scarabeo.auth import AuthContext, Role, AuthMode
        
        viewer = AuthContext(
            tenant_id="test", user_id=None, role=Role.VIEWER,
            auth_mode=AuthMode.HEADER, ip_address=None, user_agent=None,
        )
        analyst = AuthContext(
            tenant_id="test", user_id=None, role=Role.ANALYST,
            auth_mode=AuthMode.HEADER, ip_address=None, user_agent=None,
        )
        admin = AuthContext(
            tenant_id="test", user_id=None, role=Role.ADMIN,
            auth_mode=AuthMode.HEADER, ip_address=None, user_agent=None,
        )

        # Viewer can only access viewer
        assert viewer.has_permission(Role.VIEWER) is True
        assert viewer.has_permission(Role.ANALYST) is False
        assert viewer.has_permission(Role.ADMIN) is False

        # Analyst can access viewer and analyst
        assert analyst.has_permission(Role.VIEWER) is True
        assert analyst.has_permission(Role.ANALYST) is True
        assert analyst.has_permission(Role.ADMIN) is False

        # Admin can access all
        assert admin.has_permission(Role.VIEWER) is True
        assert admin.has_permission(Role.ANALYST) is True
        assert admin.has_permission(Role.ADMIN) is True

    def test_authenticate_from_headers_success(self):
        """Test successful header authentication."""
        from scarabeo.auth import authenticate_from_headers, Role
        
        headers = {
            "X-Tenant-Id": "test-tenant",
            "X-User-Id": "user123",
            "X-Role": "analyst",
        }
        auth = authenticate_from_headers(headers)
        
        assert auth.tenant_id == "test-tenant"
        assert auth.user_id == "user123"
        assert auth.role == Role.ANALYST

    def test_authenticate_from_headers_missing_tenant(self):
        """Test authentication fails without tenant ID."""
        from scarabeo.auth import authenticate_from_headers, AuthError
        
        headers = {"X-User-Id": "user123"}
        with pytest.raises(AuthError) as exc_info:
            authenticate_from_headers(headers)
        assert exc_info.value.status_code == 400

    def test_authenticate_from_headers_invalid_tenant(self):
        """Test authentication fails with invalid tenant ID."""
        from scarabeo.auth import authenticate_from_headers, AuthError
        
        headers = {"X-Tenant-Id": "invalid@tenant"}
        with pytest.raises(AuthError) as exc_info:
            authenticate_from_headers(headers)
        assert exc_info.value.status_code == 400

    def test_require_role_success(self):
        """Test successful role requirement."""
        from scarabeo.auth import AuthContext, Role, AuthMode, require_role
        
        auth = AuthContext(
            tenant_id="test", user_id=None, role=Role.ANALYST,
            auth_mode=AuthMode.HEADER, ip_address=None, user_agent=None,
        )
        # Should not raise
        require_role(auth, Role.VIEWER)
        require_role(auth, Role.ANALYST)

    def test_require_role_forbidden(self):
        """Test forbidden on insufficient role."""
        from scarabeo.auth import AuthContext, Role, AuthMode, require_role, ForbiddenError
        
        auth = AuthContext(
            tenant_id="test", user_id=None, role=Role.VIEWER,
            auth_mode=AuthMode.HEADER, ip_address=None, user_agent=None,
        )
        with pytest.raises(ForbiddenError) as exc_info:
            require_role(auth, Role.ANALYST)
        assert exc_info.value.status_code == 403


class TestRateLimiter:
    """Tests for rate limiting."""

    @patch('scarabeo.rate_limit.get_redis_client')
    def test_check_upload_limit_allowed(self, mock_redis_factory):
        """Test rate limit allows under-limit requests."""
        from scarabeo.rate_limit import RateLimiter, RateLimitConfig
        
        mock_redis = MagicMock()
        mock_redis.zremrangebyscore.return_value = None
        mock_redis.zcard.return_value = 5  # Under limit of 60
        mock_redis.zadd.return_value = None
        mock_redis.expire.return_value = None
        mock_redis.pipeline.return_value.execute.return_value = [None, 5]
        
        mock_redis_factory.return_value = mock_redis
        
        config = RateLimitConfig(max_uploads_per_minute=60, window_seconds=60)
        limiter = RateLimiter(mock_redis, config)
        
        allowed, info = limiter.check_upload_limit("tenant-123")
        
        assert allowed is True
        assert info["remaining"] > 0

    @patch('scarabeo.rate_limit.get_redis_client')
    def test_check_upload_limit_exceeded(self, mock_redis_factory):
        """Test rate limit blocks over-limit requests."""
        from scarabeo.rate_limit import RateLimiter, RateLimitConfig
        
        mock_redis = MagicMock()
        mock_redis.zremrangebyscore.return_value = None
        mock_redis.zcard.return_value = 60  # At limit
        mock_redis.zrange.return_value = [("key", time.time())]
        
        mock_redis_factory.return_value = mock_redis
        
        config = RateLimitConfig(max_uploads_per_minute=60, window_seconds=60)
        limiter = RateLimiter(mock_redis, config)
        
        allowed, info = limiter.check_upload_limit("tenant-123")
        
        assert allowed is False
        assert info["remaining"] == 0
        assert "retry_after" in info

    @patch('scarabeo.rate_limit.get_redis_client')
    def test_check_concurrent_jobs_allowed(self, mock_redis_factory):
        """Test concurrent job limit allows under-limit."""
        from scarabeo.rate_limit import RateLimiter, RateLimitConfig
        
        mock_redis = MagicMock()
        mock_redis.get.return_value = "5"  # 5 running, under limit of 10
        
        mock_redis_factory.return_value = mock_redis
        
        config = RateLimitConfig(max_concurrent_jobs=10)
        limiter = RateLimiter(mock_redis, config)
        
        allowed, info = limiter.check_concurrent_jobs("tenant-123")
        
        assert allowed is True

    @patch('scarabeo.rate_limit.get_redis_client')
    def test_check_concurrent_jobs_exceeded(self, mock_redis_factory):
        """Test concurrent job limit blocks over-limit."""
        from scarabeo.rate_limit import RateLimiter, RateLimitConfig
        
        mock_redis = MagicMock()
        mock_redis.get.return_value = "10"  # At limit
        
        mock_redis_factory.return_value = mock_redis
        
        config = RateLimitConfig(max_concurrent_jobs=10)
        limiter = RateLimiter(mock_redis, config)
        
        allowed, info = limiter.check_concurrent_jobs("tenant-123")
        
        assert allowed is False
        assert info["remaining"] == 0


class TestRetentionService:
    """Tests for retention service."""

    def test_retention_config_defaults(self):
        """Test retention config defaults."""
        from scarabeo.retention import RetentionConfig
        
        config = RetentionConfig()
        
        assert config.artifacts_days == 30
        assert config.reports_days == 90
        assert config.samples_days == 365
        assert config.metadata_days is None

    def test_get_retention_days(self):
        """Test getting retention days by type."""
        from scarabeo.retention import RetentionConfig
        
        config = RetentionConfig(
            artifacts_days=15,
            reports_days=60,
            samples_days=180,
        )
        
        assert config.get_retention_days("artifacts") == 15
        assert config.get_retention_days("reports") == 60
        assert config.get_retention_days("samples") == 180
        assert config.get_retention_days("metadata") is None
        assert config.get_retention_days("unknown") is None

    @patch('scarabeo.retention.get_retention_config')
    def test_delete_sample_artifacts_dry_run(self, mock_config_factory):
        """Test artifact deletion in dry-run mode."""
        from scarabeo.retention import RetentionService, RetentionConfig
        
        mock_db = MagicMock()
        mock_storage = MagicMock()
        config = RetentionConfig()
        mock_config_factory.return_value = config
        
        service = RetentionService(mock_db, mock_storage, config)
        
        result = service.delete_sample_artifacts(
            tenant_id="test",
            sha256="a" * 64,
            dry_run=True,
        )
        
        assert result["dry_run"] is True
        assert result["deleted"] == []  # Nothing actually deleted in dry run


class TestStructuredLogging:
    """Tests for structured logging."""

    def test_structured_formatter_produces_json(self):
        """Test structured formatter produces valid JSON."""
        from scarabeo.logging import StructuredFormatter
        import logging
        
        formatter = StructuredFormatter(service_name="test")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        
        output = formatter.format(record)
        parsed = json.loads(output)
        
        assert parsed["level"] == "INFO"
        assert parsed["message"] == "Test message"
        assert parsed["service"] == "test"

    def test_structured_formatter_includes_extra(self):
        """Test structured formatter includes extra fields."""
        from scarabeo.logging import StructuredFormatter
        import logging
        
        formatter = StructuredFormatter(service_name="test")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.tenant_id = "test-tenant"
        record.sample_sha256 = "abc123"
        
        output = formatter.format(record)
        parsed = json.loads(output)
        
        assert parsed["tenant_id"] == "test-tenant"
        assert parsed["sample_sha256"] == "abc123"


class TestMetricsCollector:
    """Tests for metrics collection."""

    def test_metrics_collector_initialization(self):
        """Test metrics collector initializes correctly."""
        from scarabeo.metrics import MetricsCollector, MetricsConfig
        
        config = MetricsConfig(enabled=True, prefix="test")
        collector = MetricsCollector(config)
        
        assert collector.requests_total is not None
        assert collector.jobs_total is not None
        assert collector.uploads_bytes is not None

    def test_metrics_collector_disabled(self):
        """Test metrics collector when disabled."""
        from scarabeo.metrics import MetricsCollector, MetricsConfig
        
        config = MetricsConfig(enabled=False)
        collector = MetricsCollector(config)
        
        # Metrics should be None when disabled
        assert collector.requests_total is None

    def test_record_request(self):
        """Test recording request metrics."""
        from scarabeo.metrics import MetricsCollector, MetricsConfig
        
        config = MetricsConfig(enabled=True, prefix="test")
        collector = MetricsCollector(config)
        
        # Should not raise
        collector.record_request(
            route="/samples",
            method="POST",
            status=200,
            duration=0.5,
            service="ingest",
        )

    def test_get_metrics_returns_bytes(self):
        """Test getting metrics returns bytes."""
        from scarabeo.metrics import MetricsCollector, MetricsConfig
        
        config = MetricsConfig(enabled=True, prefix="test")
        collector = MetricsCollector(config)
        
        metrics = collector.get_metrics()
        
        assert isinstance(metrics, bytes)
        assert len(metrics) > 0


class TestAuditLogFields:
    """Tests for audit log field completeness."""

    def test_audit_log_has_all_fields(self):
        """Test audit log model has all required fields."""
        from services.ingest.models import AuditLog
        
        # Check columns exist
        columns = [c.name for c in AuditLog.__table__.columns]
        
        required_fields = [
            "id", "tenant_id", "user_id", "role", "action",
            "target_type", "target_id", "status", "ip_address",
            "user_agent", "details_json", "created_at",
        ]
        
        for field in required_fields:
            assert field in columns, f"Missing field: {field}"
