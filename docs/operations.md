# Operations Runbook

## Local Development Setup

### Prerequisites

- Docker and Docker Compose
- Python 3.11+
- Make (optional but recommended)

### Quick Start

```bash
# 1. Initialize environment
make init

# 2. Start infrastructure
make up

# 3. Run database migrations
make migrate

# 4. Build analyzer images
make build-analyzers

# 5. Start all services
make up-all
```

## Service Endpoints

| Service | Port | Endpoints |
|---------|------|-----------|
| Ingest | 8000 | `/samples`, `/healthz`, `/readyz`, `/metrics` |
| Orchestrator | 8001 | `/jobs/{id}`, `/healthz`, `/readyz`, `/metrics` |
| MinIO Console | 9001 | http://localhost:9001 |
| PostgreSQL | 5432 | localhost:5432 |
| Redis | 6379 | localhost:6379 |

## Authentication

### Header Mode (Default)

```bash
# Upload sample (requires analyst role)
curl -X POST http://localhost:8000/samples \
  -H "X-Tenant-Id: my-tenant" \
  -H "X-User-Id: user123" \
  -H "X-Role: analyst" \
  -F "file=@test_sample.exe"

# List samples (requires viewer role)
curl http://localhost:8000/samples \
  -H "X-Tenant-Id: my-tenant" \
  -H "X-Role: viewer"
```

### OIDC Mode

```bash
# Set environment
export AUTH_MODE=oidc
export OIDC_JWKS_URL=https://auth.example.com/.well-known/jwks.json
export OIDC_AUDIENCE=scarabeo-api
export OIDC_ISSUER=https://auth.example.com

# Use Bearer token
curl -X POST http://localhost:8000/samples \
  -H "Authorization: Bearer <jwt_token>" \
  -F "file=@test_sample.exe"
```

## Metrics & Observability

### Prometheus Metrics

```bash
# Scrape metrics
curl http://localhost:8000/metrics
curl http://localhost:8001/metrics
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `scarabeo_requests_total` | HTTP requests |
| `scarabeo_jobs_total` | Jobs processed |
| `scarabeo_uploads_bytes` | Upload sizes |
| `scarabeo_analyzer_runs_total` | Analyzer executions |
| `scarabeo_rate_limit_hits_total` | Rate limit triggers |

### Structured Logging

All services output JSON logs:

```json
{
  "timestamp": "2024-01-15T10:00:00Z",
  "level": "INFO",
  "service": "ingest",
  "message": "Sample submitted",
  "tenant_id": "my-tenant",
  "user_id": "user123",
  "sample_sha256": "abc123...",
  "event": "sample_upload"
}
```

## Health Checks

```bash
# Liveness
curl http://localhost:8000/healthz
curl http://localhost:8001/healthz

# Readiness (checks dependencies)
curl http://localhost:8000/readyz
curl http://localhost:8001/readyz
```

## Retention

### Run Retention

```bash
# Dry run (no actual deletion)
make retention-dry-run

# Actual deletion
make retention-run

# With custom batch size
python -m services.worker.retention --batch-size=50
```

### Configure Retention

```bash
# Environment variables
export RETENTION_ARTIFACTS_DAYS=30
export RETENTION_REPORTS_DAYS=90
export RETENTION_SAMPLES_DAYS=365
```

## Rate Limits

### Configuration

```bash
export RATE_LIMIT_UPLOADS_PER_MINUTE=60
export RATE_LIMIT_CONCURRENT_JOBS=10
```

### Monitor Rate Limits

```bash
# Check rate limit hits in metrics
curl http://localhost:8000/metrics | grep rate_limit
```

## Configuration

### Environment Variables

| Variable | Service | Default |
|----------|---------|---------|
| `AUTH_MODE` | All | `header` |
| `LOG_LEVEL` | All | `INFO` |
| `METRICS_ENABLED` | All | `true` |
| `RATE_LIMIT_UPLOADS_PER_MINUTE` | Ingest | `60` |
| `RETENTION_ARTIFACTS_DAYS` | Worker | `30` |

See `services/*/\.env.example` for full configuration.

## Troubleshooting

### Database Connection Issues

```bash
# Check PostgreSQL is running
docker-compose -f infra/docker-compose.yml ps postgres

# View logs
docker-compose -f infra/docker-compose.yml logs postgres

# Test connection
psql -h localhost -U scarabeo -d scarabeo
```

### Redis Connection Issues

```bash
# Check Redis is running
docker-compose -f infra/docker-compose.yml ps redis

# Test connection
redis-cli -h localhost -a scarabeo_dev_password ping
```

### MinIO/S3 Issues

```bash
# Check MinIO is running
docker-compose -f infra/docker-compose.yml ps minio

# View bucket contents via console
# Open http://localhost:9001 and login with scarabeo/scarabeo_dev_password
```

### Job Stuck in QUEUED Status

1. Check orchestrator is running and consuming from queue
2. Check Redis queue: `redis-cli -a scarabeo_dev_password llen scarabeo:jobs:triage`
3. Check worker dispatch queue: `redis-cli -a scarabeo_dev_password llen scarabeo:workers:dispatch`
4. Verify worker is running and processing jobs

### Job Stuck in RUNNING Status

1. Check worker logs for errors
2. Verify Docker socket access for worker
3. Check if analyzer container failed to start
4. Retry job via orchestrator API

## Monitoring

### Queue Depths

```bash
# Ingest queue
redis-cli -a scarabeo_dev_password llen scarabeo:jobs:triage

# Worker dispatch queue
redis-cli -a scarabeo_dev_password llen scarabeo:workers:dispatch
```

### Database Queries

```sql
-- Count jobs by status
SELECT status, COUNT(*) FROM jobs GROUP BY status;

-- Recent jobs
SELECT id, status, pipeline_name, created_at FROM jobs ORDER BY created_at DESC LIMIT 10;

-- Samples by tenant
SELECT tenant_id, COUNT(*) FROM samples GROUP BY tenant_id;
```

## Backup and Restore

### Database Backup

```bash
# Backup
docker exec scarabeo-postgres pg_dump -U scarabeo scarabeo > backup.sql

# Restore
docker exec -i scarabeo-postgres psql -U scarabeo scarabeo < backup.sql
```

### S3 Backup

Use MinIO client (`mc`) to backup bucket contents:

```bash
mc alias set backup http://localhost:9000 scarabeo scarabeo_dev_password
mc mirror backup/scarabeo-samples ./backup/s3/
```
