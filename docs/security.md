# Security Requirements

## Overview

Scarabeo handles potentially malicious code. This document defines security requirements for isolation, output sanitization, authentication, authorization, and operational security.

## Authentication & Authorization

### Auth Modes

Scarabeo supports two authentication modes:

#### Header Mode (Default)

Simple header-based authentication for internal deployments:

| Header | Required | Description |
|--------|----------|-------------|
| `X-Tenant-Id` | Yes | Tenant identifier |
| `X-User-Id` | No | User identifier |
| `X-Role` | No | Role (viewer, analyst, admin) |

#### OIDC Mode (Stub)

JWT-based authentication for enterprise deployments:

```bash
AUTH_MODE=oidc
OIDC_JWKS_URL=https://auth.example.com/.well-known/jwks.json
OIDC_AUDIENCE=scarabeo-api
OIDC_ISSUER=https://auth.example.com
```

### RBAC Roles

| Role | Permissions |
|------|-------------|
| `viewer` | Read samples, reports, jobs |
| `analyst` | Upload samples, view all |
| `admin` | Full access including job retry |

### Endpoint Authorization

| Endpoint | Required Role |
|----------|---------------|
| `GET /samples` | viewer |
| `GET /samples/{sha256}` | viewer |
| `GET /samples/{sha256}/report` | viewer |
| `POST /samples` | analyst |
| `GET /jobs/{id}` | viewer |
| `POST /jobs/{id}/retry` | admin |

## Rate Limits & Quotas

### Per-Tenant Rate Limits

| Limit | Default | Config |
|-------|---------|--------|
| Uploads per minute | 60 | `RATE_LIMIT_UPLOADS_PER_MINUTE` |
| Concurrent jobs | 10 | `RATE_LIMIT_CONCURRENT_JOBS` |

### Quotas

| Quota | Default | Config |
|-------|---------|--------|
| Max storage | 10GB | `QUOTA_MAX_STORAGE_BYTES` |
| Max analyses/day | 1000 | `QUOTA_MAX_ANALYSES_PER_DAY` |
| Max file size | 50MB | `QUOTA_MAX_FILE_SIZE_BYTES` |

### Rate Limit Response

```json
{
  "error": "rate_limit_exceeded",
  "message": "Upload limit exceeded: 60 per minute",
  "retry_after": 45
}
```

## Retention & Data Deletion

### Default Retention Periods

| Resource | Retention | Config |
|----------|-----------|--------|
| Artifacts | 30 days | `RETENTION_ARTIFACTS_DAYS` |
| Reports | 90 days | `RETENTION_REPORTS_DAYS` |
| Samples | 365 days | `RETENTION_SAMPLES_DAYS` |
| Metadata | Indefinite | `RETENTION_METADATA_DAYS` (none) |

### Running Retention

```bash
# Dry run
make retention-dry-run

# Actual deletion
make retention-run
```

### Retention Audit

All deletions are logged in `audit_log` with:
- `action`: "retention_deletion"
- `details_json`: Contains sha256, reason

## Isolation Requirements

### Container Isolation

All analyzer containers run with:

| Setting | Value |
|---------|-------|
| Network | Disabled |
| Root filesystem | Read-only |
| Capabilities | All dropped |
| Security options | no-new-privileges, seccomp:default |
| PID limit | 50 |
| File descriptors | 1024 |
| Processes | 256 |
| tmpfs | noexec, nosuid |

### Worker Hardening

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

## Output Sanitization

### Artifact Preview

- Text previews Base64 encoded
- Maximum 1KB preview
- Control characters stripped

### IOC Handling

- URLs defanged: `hxxp://` instead of `http://`
- Domains may be redacted in logs
- Never auto-access IOCs

### Log Sanitization

- Tenant IDs isolated in logging
- No sample content in logs
- API keys never logged

## Audit Logging

### Audit Log Fields

| Field | Description |
|-------|-------------|
| `tenant_id` | Tenant identifier |
| `user_id` | User identifier |
| `role` | User role at time of action |
| `action` | Action type |
| `target_type` | Resource type |
| `target_id` | Resource identifier |
| `status` | Action status |
| `ip_address` | Client IP |
| `user_agent` | Client user agent |
| `details_json` | Additional details |
| `created_at` | Timestamp |

### Audited Actions

- Sample uploads/downloads
- Job creation/completion/failure
- Job retries
- Retention deletions
- Authentication failures

## Observability

### Metrics

Prometheus metrics exposed at `/metrics`:

| Metric | Description |
|--------|-------------|
| `scarabeo_requests_total` | HTTP requests by route/status |
| `scarabeo_jobs_total` | Jobs by status/pipeline |
| `scarabeo_job_duration_seconds` | Job duration histogram |
| `scarabeo_uploads_bytes` | Upload size histogram |
| `scarabeo_analyzer_runs_total` | Analyzer runs by status |
| `scarabeo_rate_limit_hits_total` | Rate limit hits |

### Structured Logging

JSON logs with fields:
- `timestamp`, `level`, `service`
- `tenant_id`, `user_id`, `request_id`
- `job_id`, `sample_sha256`, `event`

### Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `/healthz` | Liveness probe |
| `/readyz` | Readiness with dependency checks |

## Security Configuration

### Environment Variables

```bash
# Auth
AUTH_MODE=header
# OIDC (if enabled)
OIDC_JWKS_URL=...
OIDC_AUDIENCE=...
OIDC_ISSUER=...

# Rate limits
RATE_LIMIT_UPLOADS_PER_MINUTE=60
RATE_LIMIT_CONCURRENT_JOBS=10

# Retention
RETENTION_ARTIFACTS_DAYS=30
RETENTION_REPORTS_DAYS=90

# Logging
LOG_LEVEL=INFO
SERVICE_NAME=ingest

# Metrics
METRICS_ENABLED=true
METRICS_PREFIX=scarabeo
```

## Incident Response

### Escape Detection

- Monitor for unexpected network from workers
- Alert on container breakout attempts
- Auto-quarantine on anomaly

### Containment

1. Terminate worker immediately
2. Isolate network
3. Preserve sample for forensics

### Recovery

1. Recreate workers from known-good images
2. Reconstruct pipeline state
3. Post-incident hardening

## Compliance

### Data Retention

- Configurable per tenant
- Automatic purging
- Legal hold capability

### Multi-tenancy

- Logical isolation via `tenant_id`
- Cross-tenant access prohibited
- All access audited

### Supply Chain Security

- Container images signed
- Dependency scanning in CI/CD
- SBOM for releases
