"""Prometheus metrics for SCARABEO services."""

import os
import time
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
)


@dataclass
class MetricsConfig:
    """Metrics configuration."""

    enabled: bool = True
    prefix: str = "scarabeo"


@lru_cache
def get_metrics_config() -> MetricsConfig:
    """Get cached metrics configuration."""
    enabled = os.environ.get("METRICS_ENABLED", "true").lower() == "true"
    prefix = os.environ.get("METRICS_PREFIX", "scarabeo")
    return MetricsConfig(enabled=enabled, prefix=prefix)


class MetricsCollector:
    """Prometheus metrics collector."""

    def __init__(self, config: MetricsConfig | None = None):
        self.config = config or get_metrics_config()
        self.registry = CollectorRegistry()

        # Initialize all metric attributes to None (overwritten when enabled)
        self.requests_total = None
        self.request_duration = None
        self.jobs_total = None
        self.job_duration = None
        self.jobs_running = None
        self.uploads_total = None
        self.uploads_bytes = None
        self.analyzer_runs_total = None
        self.analyzer_duration = None
        self.queue_depth = None
        self.rate_limit_hits_total = None
        self.storage_bytes = None
        self.search_queries_total = None
        self.cases_total = None
        self.intel_iocs_total = None
        self.verdicts_total = None
        self.notes_total = None
        self.exports_total = None
        self.clusters_total = None
        self.cluster_members_total = None

        if not self.config.enabled:
            return

        self._register_metrics()

    def _register_metrics(self) -> None:
        """Register all metrics."""
        prefix = self.config.prefix

        # Request metrics
        self.requests_total = Counter(
            f"{prefix}_requests_total",
            "Total HTTP requests",
            ["service", "route", "method", "status"],
            registry=self.registry,
        )

        self.request_duration = Histogram(
            f"{prefix}_request_duration_seconds",
            "HTTP request duration in seconds",
            ["service", "route", "method"],
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
            registry=self.registry,
        )

        # Job metrics
        self.jobs_total = Counter(
            f"{prefix}_jobs_total",
            "Total jobs processed",
            ["service", "status", "pipeline"],
            registry=self.registry,
        )

        self.job_duration = Histogram(
            f"{prefix}_job_duration_seconds",
            "Job processing duration in seconds",
            ["service", "pipeline"],
            buckets=(1, 5, 10, 30, 60, 120, 300, 600),
            registry=self.registry,
        )

        self.jobs_running = Gauge(
            f"{prefix}_jobs_running",
            "Currently running jobs",
            ["service", "pipeline"],
            registry=self.registry,
        )

        # Upload metrics
        self.uploads_total = Counter(
            f"{prefix}_uploads_total",
            "Total sample uploads",
            ["service", "status", "file_type"],
            registry=self.registry,
        )

        self.uploads_bytes = Histogram(
            f"{prefix}_uploads_bytes",
            "Sample upload size in bytes",
            ["service"],
            buckets=(1024, 10240, 102400, 1048576, 10485760, 52428800),
            registry=self.registry,
        )

        # Analyzer metrics
        self.analyzer_runs_total = Counter(
            f"{prefix}_analyzer_runs_total",
            "Total analyzer runs",
            ["service", "analyzer", "status"],
            registry=self.registry,
        )

        self.analyzer_duration = Histogram(
            f"{prefix}_analyzer_duration_seconds",
            "Analyzer execution duration in seconds",
            ["service", "analyzer"],
            buckets=(1, 5, 10, 30, 60, 120, 300),
            registry=self.registry,
        )

        # Queue metrics
        self.queue_depth = Gauge(
            f"{prefix}_queue_depth",
            "Current queue depth",
            ["service", "queue"],
            registry=self.registry,
        )

        # Rate limit metrics
        self.rate_limit_hits_total = Counter(
            f"{prefix}_rate_limit_hits_total",
            "Total rate limit hits",
            ["service", "tenant_id", "limit_type"],
            registry=self.registry,
        )

        # Storage metrics
        self.storage_bytes = Gauge(
            f"{prefix}_storage_bytes",
            "Total storage used",
            ["service", "tenant_id"],
            registry=self.registry,
        )

        # Search metrics
        self.search_queries_total = Counter(
            f"{prefix}_search_queries_total",
            "Total search queries",
            ["service", "status"],
            registry=self.registry,
        )

        # Case metrics
        self.cases_total = Gauge(
            f"{prefix}_cases_total",
            "Total cases",
            ["service", "tenant_id"],
            registry=self.registry,
        )

        # IOC intelligence metrics
        self.intel_iocs_total = Gauge(
            f"{prefix}_intel_iocs_total",
            "Total unique IOCs tracked",
            ["service", "ioc_type"],
            registry=self.registry,
        )

        # Verdict metrics
        self.verdicts_total = Counter(
            f"{prefix}_verdicts_total",
            "Total verdicts set",
            ["service", "verdict"],
            registry=self.registry,
        )

        # Notes metrics
        self.notes_total = Counter(
            f"{prefix}_notes_total",
            "Total notes created",
            ["service"],
            registry=self.registry,
        )

        # Export metrics
        self.exports_total = Counter(
            f"{prefix}_exports_total",
            "Total exports",
            ["service"],
            registry=self.registry,
        )

        # Clustering metrics
        self.clusters_total = Counter(
            f"{prefix}_clusters_total",
            "Total clusters created",
            ["service", "algorithm"],
            registry=self.registry,
        )

        self.cluster_members_total = Counter(
            f"{prefix}_cluster_members_total",
            "Total cluster members added",
            ["service", "algorithm"],
            registry=self.registry,
        )

    def record_request(
        self,
        route: str,
        method: str,
        status: int,
        duration: float,
        service: str | None = None,
    ) -> None:
        """Record HTTP request metrics."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.requests_total.labels(
            service=service,
            route=route,
            method=method,
            status=status,
        ).inc()

        self.request_duration.labels(
            service=service,
            route=route,
            method=method,
        ).observe(duration)

    def record_job(
        self,
        status: str,
        pipeline: str,
        duration: float,
        service: str | None = None,
    ) -> None:
        """Record job metrics."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.jobs_total.labels(
            service=service,
            status=status,
            pipeline=pipeline,
        ).inc()

        self.job_duration.labels(
            service=service,
            pipeline=pipeline,
        ).observe(duration)

    def record_upload(
        self,
        status: int,
        file_type: str,
        size_bytes: int,
        service: str | None = None,
    ) -> None:
        """Record upload metrics."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.uploads_total.labels(
            service=service,
            status=status,
            file_type=file_type,
        ).inc()

        self.uploads_bytes.labels(service=service).observe(size_bytes)

    def record_analyzer_run(
        self,
        analyzer: str,
        status: str,
        duration: float,
        service: str | None = None,
    ) -> None:
        """Record analyzer run metrics."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.analyzer_runs_total.labels(
            service=service,
            analyzer=analyzer,
            status=status,
        ).inc()

        self.analyzer_duration.labels(
            service=service,
            analyzer=analyzer,
        ).observe(duration)

    def record_rate_limit_hit(
        self,
        tenant_id: str,
        limit_type: str,
        service: str | None = None,
    ) -> None:
        """Record rate limit hit."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.rate_limit_hits_total.labels(
            service=service,
            tenant_id=tenant_id,
            limit_type=limit_type,
        ).inc()

    def set_queue_depth(self, queue: str, depth: int, service: str | None = None) -> None:
        """Set queue depth gauge."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.queue_depth.labels(service=service, queue=queue).set(depth)

    def set_jobs_running(self, count: int, pipeline: str, service: str | None = None) -> None:
        """Set running jobs gauge."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.jobs_running.labels(service=service, pipeline=pipeline).set(count)

    def record_search_query(self, status: int, service: str | None = None) -> None:
        """Record search query metric."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        status_str = str(status)
        self.search_queries_total.labels(service=service, status=status_str).inc()

    def set_cases_total(self, count: int, tenant_id: str, service: str | None = None) -> None:
        """Set cases total gauge."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.cases_total.labels(service=service, tenant_id=tenant_id).set(count)

    def set_intel_iocs_total(self, count: int, ioc_type: str, service: str | None = None) -> None:
        """Set IOC intelligence total gauge."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.intel_iocs_total.labels(service=service, ioc_type=ioc_type).set(count)

    def record_verdict(self, verdict: str, service: str | None = None) -> None:
        """Record verdict metric."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.verdicts_total.labels(service=service, verdict=verdict).inc()

    def record_note(self, service: str | None = None) -> None:
        """Record note creation metric."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.notes_total.labels(service=service).inc()

    def record_export(self, service: str | None = None) -> None:
        """Record export metric."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.exports_total.labels(service=service).inc()

    def record_cluster_created(self, algorithm: str, service: str | None = None) -> None:
        """Record cluster creation metric."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.clusters_total.labels(service=service, algorithm=algorithm).inc()

    def record_cluster_member_added(self, algorithm: str, service: str | None = None) -> None:
        """Record cluster member addition metric."""
        if not self.config.enabled:
            return

        service = service or os.environ.get("SERVICE_NAME", "unknown")
        self.cluster_members_total.labels(service=service, algorithm=algorithm).inc()

    def get_metrics(self) -> bytes:
        """Get Prometheus metrics in text format."""
        if not self.config.enabled:
            return b""

        return generate_latest(self.registry)

    def get_content_type(self) -> str:
        """Get Prometheus content type."""
        return CONTENT_TYPE_LATEST


# Global metrics collector
_metrics_collector: MetricsCollector | None = None


def get_metrics_collector() -> MetricsCollector:
    """Get global metrics collector."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def init_metrics() -> MetricsCollector:
    """Initialize metrics collector."""
    global _metrics_collector
    _metrics_collector = MetricsCollector()
    return _metrics_collector


class MetricsMiddleware:
    """FastAPI middleware for metrics."""

    def __init__(self, service_name: str | None = None):
        self.service_name = service_name or os.environ.get("SERVICE_NAME", "unknown")
        self.collector = get_metrics_collector()

    async def __call__(self, scope, receive, send) -> None:
        """Middleware for recording request metrics."""
        if scope["type"] != "http":
            await send(scope)
            return

        start_time = time.time()

        # Track request
        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                status = message["status"]
                route = scope.get("path", "unknown")
                method = scope.get("method", "unknown")
                duration = time.time() - start_time

                self.collector.record_request(
                    route=route,
                    method=method,
                    status=status,
                    duration=duration,
                    service=self.service_name,
                )

            await send(message)

        await send(scope)
