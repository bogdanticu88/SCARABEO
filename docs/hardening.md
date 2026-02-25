# Hardening Guide

This document covers the security assumptions baked into SCARABEO and the
controls that enforce them. It is intended for operators deploying in production
and for contributors adding new features.

---

## 1. Local-Only Ollama (AI explanation layer)

### Why the guardrail exists

`scarabeo/explain.py` contains `OllamaExplainerProvider`, which sends finding
data — potentially including victim artefacts, file paths, and network IOCs —
to a language model endpoint. Sending this data to an external service would:

- Create a data-exfiltration path for sensitive analysis artefacts.
- Leak indicators of compromise to third-party infrastructure.
- Violate data-residency requirements common in enterprise SOC deployments.

### How it is enforced

```python
# scarabeo/explain.py
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

def _assert_local_endpoint(url: str) -> None:
    host = urlparse(url).hostname or ""
    if host not in _LOCAL_HOSTS:
        raise LocalEndpointViolation(f"Non-local endpoint rejected: {url}")
```

The check runs at provider construction time, not at request time, so there is
no window in which a misconfigured URL can leak data.

### Allowed endpoints

| URL | Accepted |
|-----|----------|
| `http://localhost:11434` | Yes |
| `http://127.0.0.1:11434` | Yes |
| `http://[::1]:11434` | Yes |
| `http://10.0.0.5:11434` | **No** — private LAN, still remote |
| `https://api.external.ai/v1` | **No** |

Private RFC-1918 addresses (`10.x`, `172.16-31.x`, `192.168.x`) are rejected.
Loopback only means the model must run on the same host as the worker process.

### Overriding for air-gapped lab deployments

If Ollama is running on a dedicated GPU host inside a controlled network with
no internet egress, you can disable the check:

```python
provider = OllamaExplainerProvider(
    base_url="http://10.0.1.50:11434",
    allow_remote=True,   # operator assumes responsibility
)
```

Set `allow_remote=True` only when:
- The endpoint host has no internet egress.
- Network traffic is monitored.
- No raw sample bytes are included in the prompt (SCARABEO only sends
  finding metadata, not binary content).

### Config flags

| Setting | Default | Description |
|---------|---------|-------------|
| `EXPLAINER_ENABLED` | `false` | Enable/disable the explanation layer |
| `EXPLAINER_ENDPOINT` | `http://localhost:11434` | Ollama base URL |
| `EXPLAINER_MODEL` | `mistral:7b` | Model name |
| `EXPLAINER_TIMEOUT` | `60` | Request timeout in seconds |

---

## 2. Analyzer Container Isolation

Each analysis job spawns a short-lived Docker container with a hardened
security posture. The worker service (`services/worker/`) enforces these flags
unconditionally.

### Container security flags

| Flag | Value | Effect |
|------|-------|--------|
| `--network none` | always | No internet or LAN access during analysis |
| `--read-only` | always | Root filesystem is read-only |
| `--tmpfs /tmp` | always | Writable scratch space is in-memory only |
| `--cpus 2.0` | configurable | Prevents CPU exhaustion |
| `--memory 2g` | configurable | Prevents memory exhaustion |
| `--pids-limit 256` | always | Prevents fork bombs |
| `--cap-drop ALL` | always | No Linux capabilities |
| `--security-opt no-new-privileges` | always | Cannot escalate via setuid |

Configuration knobs (all in `services/worker/config.py`):

```bash
DOCKER_NETWORK_DISABLED=true   # must stay true in production
DOCKER_READONLY_ROOTFS=true    # must stay true in production
DOCKER_CPU_LIMIT=2.0
DOCKER_MEMORY_LIMIT=2g
```

### Work directory model

The worker mounts exactly two paths into the container:

| Host path | Container path | Access |
|-----------|---------------|--------|
| `{job_dir}/input.json` | `/work/input.json` | Read-only |
| `{job_dir}/out/` | `/work/out/` | Read-write (via tmpfs) |

The sample binary is placed in `{job_dir}/` before the container starts and
bind-mounted read-only. The container cannot modify the sample, cannot write to
the host outside `/work/out/`, and cannot reach any network.

### What the container is allowed to do

- Read `/work/input.json` (job metadata + analysis options).
- Read the sample binary from `/work/sample` (read-only bind mount).
- Write structured JSON output to `/work/out/report.json`.
- Write artifact files (strings, imports, entropy map) to `/work/out/artifacts/`.

### What the container cannot do

- Make any network connection.
- Write outside `/work/out/`.
- Fork more than 256 child processes.
- Load kernel modules or change system settings.
- Access the host Docker socket.

### Image provenance

Analyzer images are built from pinned base images and scanned before use:

```dockerfile
FROM python:3.11-slim-bookworm@sha256:<digest>  # pin to digest, not tag
```

The worker records the image digest in the report's `provenance.engines[].version`
field. Any discrepancy between the recorded digest and the running image should
be treated as a supply-chain anomaly.

---

## 3. Authentication and Multi-Tenancy

### Header-based auth (default)

SCARABEO uses request headers for identity — appropriate for internal SOC
deployments where the reverse proxy enforces mTLS or token injection.

| Header | Required | Values |
|--------|----------|--------|
| `X-Tenant-Id` | Yes | Arbitrary string; separates all data |
| `X-User-Id` | No | Logged in audit trail |
| `X-Role` | No | `viewer` / `analyst` / `admin` |

Every database query includes a `WHERE tenant_id = ?` predicate. There is no
superuser query path that bypasses this filter. Cross-tenant access is not
possible at the ORM layer.

### Role enforcement

| Operation | viewer | analyst | admin |
|-----------|--------|---------|-------|
| Read reports, IOCs, jobs | ✓ | ✓ | ✓ |
| Upload samples | — | ✓ | ✓ |
| Set verdict, add notes/tags | — | ✓ | ✓ |
| Retry / delete jobs | — | — | ✓ |
| Access metrics endpoint | — | — | ✓ |

### Audit logging

Every mutating operation (upload, verdict, tag, note) is logged with:
- `tenant_id` and `user_id`
- Source IP (from reverse proxy header)
- Timestamp and operation type

Logs are structured JSON (via `scarabeo/logging.py`) and should be shipped to
a SIEM in production.

---

## 4. Object Storage (S3/MinIO)

Sample binaries and analysis artefacts are stored in MinIO/S3. Security
assumptions:

- **Single bucket** (`scarabeo-samples`) — access is controlled at the
  application layer, not via bucket policies (simplifies IAM).
- **Object keys include `tenant_id`**: `{tenant_id}/{sha256}/sample` —
  a misconfigured presigned URL leaks at most one sample for one tenant.
- **No public access** — the bucket must have public access disabled.
- **Encryption at rest** — enable SSE-S3 or SSE-KMS in production MinIO/S3.

Presigned URL TTL is 300 seconds (configurable via `S3_PRESIGN_TTL`). URLs
are generated per-request and not cached.

---

## 5. Schema Validation as a Safety Net

All partial analyzer outputs are validated against
`contracts/schemas/partial.schema.json` before merging. The final merged
report is validated against `contracts/schemas/report.schema.json` after
assembly. Validation is fail-closed: a schema violation aborts the job and
marks it `FAILED` before any data is stored.

This prevents:
- Malformed analyzer output from reaching the database.
- Prompt injection via crafted finding text reaching the AI layer.
- Downstream consumers (scoring, timeline, explain) from receiving
  structurally invalid input.

See `scarabeo/validation.py` and `docs/pipelines.md` for implementation
details.

---

## 6. Rate Limiting

The ingest service enforces per-tenant upload rate limits to prevent one
tenant from monopolising the analysis queue:

```bash
RATE_LIMIT_UPLOADS_PER_MINUTE=60   # default
RATE_LIMIT_BURST=10                # burst allowance
```

Limits are tracked in Redis with a sliding-window algorithm. Exceeding the
limit returns HTTP 429.

---

## 7. Production Deployment Checklist

Before going to production:

- [ ] Change all default passwords in `.env` (`scarabeo_dev_password`).
- [ ] Set `DEBUG=false` on all services.
- [ ] Deploy behind a TLS-terminating reverse proxy (nginx, Caddy, or a
  cloud load balancer).
- [ ] Enable MinIO SSE-S3 (or use AWS S3 with SSE-KMS).
- [ ] Restrict Docker socket access — only the worker service needs it.
- [ ] Pin Ollama model pull to a known digest, verify offline.
- [ ] Disable `allow_remote=True` unless on an isolated GPU network.
- [ ] Configure log shipping to a SIEM.
- [ ] Enable `DOCKER_NETWORK_DISABLED=true` (it is the default; do not change).
- [ ] Review `DOCKER_MEMORY_LIMIT` based on expected sample size.
- [ ] Enable Prometheus scraping and set up alerts for job failure rate
  and queue depth.
