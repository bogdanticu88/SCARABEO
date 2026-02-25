<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/998b5b65-b734-4b49-8fbd-ecd741f57541" />
# Scarabeo

**Malware Analysis Framework**

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](VERSION)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Overview

SCARABEO is a modular malware analysis framework for static analysis, automated detection, and structured reporting. Designed for security engineers and threat researchers, it supports scalable pipelines, analyzer plugins, and enterprise ready workflows.

- **Multi-tenant architecture** with RBAC (viewer, analyst, admin)
- **Static analysis** with 10+ specialized analyzers
- **Isolated execution** in hardened Docker containers
- **Enterprise features**: rate limiting, retention, audit logging, observability
- **CLI console** for interactive operations
- **Kubernetes-ready** deployment manifests

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/scarabeo/scarabeo.git
cd scarabeo

# Install dependencies
pip install -e ".[all]"

# Initialize environment
make init
```

### Local Development

```bash
# Start infrastructure (Postgres, Redis, MinIO)
make up

# Run database migrations
make migrate

# Build all analyzer images
make build-analyzers

# Start all services
make up-all

# Open CLI console
make run-cli
```

### Verify Installation

```bash
# Check service health
curl http://localhost:8000/healthz
curl http://localhost:8001/healthz

# View metrics
curl http://localhost:8000/metrics
```

## CLI Usage

```bash
# Start CLI console
python -m services.cli

# Or use make
make run-cli
```

### Commands

```
scarabeo > help
scarabeo > version
scarabeo > upload malware.exe
scarabeo > status <sha256>
scarabeo > report <sha256>
scarabeo > jobs
scarabeo > verdict <sha256> malicious Ransomware detected
scarabeo > tag-add <sha256> ransomware
scarabeo > tags <sha256>
scarabeo > note <sha256> Suspicious network activity
scarabeo > export <sha256> sample.zip
scarabeo > exit
```

### Environment Configuration

```bash
export SCARABEO_API_URL=http://localhost:8000
export SCARABEO_TENANT=my-tenant
export SCARABEO_USER=my-user
export SCARABEO_ROLE=analyst
```

## API Usage

### Upload Sample

```bash
curl -X POST http://localhost:8000/samples \
  -H "X-Tenant-Id: my-tenant" \
  -H "X-User-Id: my-user" \
  -H "X-Role: analyst" \
  -F "file=@malware.exe"
```

### Get Analysis Report

```bash
curl http://localhost:8000/samples/<sha256>/report \
  -H "X-Tenant-Id: my-tenant" \
  -H "X-Role: viewer"
```

### Review Workflow

```bash
# Set verdict
curl -X POST http://localhost:8000/samples/<sha256>/verdict \
  -H "X-Tenant-Id: my-tenant" \
  -H "X-Role: analyst" \
  -H "Content-Type: application/json" \
  -d '{"verdict": "malicious", "reason": "Ransomware detected"}'

# Add tag
curl -X POST http://localhost:8000/samples/<sha256>/tags \
  -H "X-Tenant-Id: my-tenant" \
  -H "X-Role: analyst" \
  -H "Content-Type: application/json" \
  -d '{"tag": "ransomware"}'

# Add note
curl -X POST http://localhost:8000/samples/<sha256>/notes \
  -H "X-Tenant-Id: my-tenant" \
  -H "X-Role: analyst" \
  -H "Content-Type: application/json" \
  -d '{"body": "Suspicious network activity observed"}'

# Export sample data
curl http://localhost:8000/samples/<sha256>/export \
  -H "X-Tenant-Id: my-tenant" \
  -H "X-Role: viewer" \
  -o sample_export.zip
```

## Deployment

### Docker Compose

```bash
# Start all services
docker-compose -f infra/docker-compose.yml up -d

# View logs
docker-compose -f infra/docker-compose.yml logs -f
```

### Kubernetes

```bash
# Create namespace and deploy
kubectl apply -f infra/k8s/namespace.yaml
kubectl apply -f infra/k8s/

# Set secrets
export POSTGRES_PASSWORD=secure_password
export REDIS_PASSWORD=secure_password
export MINIO_ROOT_USER=admin
export MINIO_ROOT_PASSWORD=secure_password
export ADMIN_TOKEN=secure_admin_token

# Deploy with secrets
envsubst < infra/k8s/postgres.yaml | kubectl apply -f -
# ... repeat for other manifests
```

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│   Ingest    │────▶│    Redis    │
│   (CLI)     │     │   (8000)    │     │   Queue     │
└─────────────┘     └─────────────┘     └─────────────┘
                           │                   │
                           ▼                   ▼
                    ┌─────────────┐     ┌─────────────┐
                    │  PostgreSQL │     │Orchestrator │
                    │   Database  │     │   (8001)    │
                    └─────────────┘     └─────────────┘
                                              │
                                              ▼
                                       ┌─────────────┐
                                       │   Worker    │
                                       │  (Analyzer) │
                                       └─────────────┘
```

## Analyzers

| Analyzer | File Types | Description |
|----------|------------|-------------|
| triage-universal | All | Strings, entropy, IOC extraction |
| pe-analyzer | PE/EXE/DLL | PE headers, imports, packer detection |
| elf-analyzer | ELF | ELF headers, suspicious functions |
| script-analyzer | Scripts | Obfuscation detection, IOCs |
| doc-analyzer | Documents | Macros, embedded objects |
| archive-analyzer | Archives | Safe listing, extraction |
| similarity-analyzer | All | SSDEEP, TLSH hashes |
| yara-analyzer | All | YARA rules (optional) |
| capa-analyzer | PE/ELF | Capabilities (optional) |

## Configuration

### Environment Variables

| Variable | Service | Default | Description |
|----------|---------|---------|-------------|
| `AUTH_MODE` | All | `header` | Authentication mode |
| `LOG_LEVEL` | All | `INFO` | Logging level |
| `RATE_LIMIT_UPLOADS_PER_MINUTE` | Ingest | `60` | Upload rate limit |
| `RETENTION_ARTIFACTS_DAYS` | Worker | `30` | Artifact retention |

See `services/*/\.env.example` for full configuration.

## Versioning

SCARABEO follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

Current version: **1.0.0**

### Release Process

```bash
# Run release checks
make release-check

# Create release tag
make release-tag VERSION=1.0.0
```

## Documentation

- [Architecture](docs/architecture.md) - System design
- [Security](docs/security.md) - Security requirements
- [Operations](docs/operations.md) - Runbook
- [Pipelines](docs/pipelines.md) - Analyzer architecture
- [Analyzers](docs/analyzers.md) - Analyzer documentation
- [Release Guide](RELEASE.md) - Release process

## Development

```bash
# Run tests
make test

# Run linters
make lint

# Format code
make fmt

# Run coverage
make coverage
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `make test`
5. Submit a pull request

## Support

- Issues: GitHub Issues
- Documentation: docs/ directory
- Security: See docs/security.md


