# Changelog

All notable changes to SCARABEO will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-20

### Added

#### Core Features
- Initial production release
- Multi-tenant architecture with RBAC (viewer, analyst, admin roles)
- Header-based authentication with OIDC stub
- Rate limiting and quotas per tenant
- Policy-driven data retention

#### Services
- **Ingest Service**: Sample upload, storage, job queuing
- **Orchestrator Service**: Job dispatch, worker coordination
- **Worker Service**: Analyzer execution in isolated containers

#### Analyzers
- **triage-universal**: Strings, entropy, IOC extraction
- **pe-analyzer**: PE header parsing, imports, packer detection
- **elf-analyzer**: ELF headers, suspicious functions
- **script-analyzer**: Obfuscation detection, IOC extraction
- **doc-analyzer**: OLE/OOXML macro detection
- **archive-analyzer**: Safe listing, controlled extraction
- **similarity-analyzer**: SSDEEP, TLSH hashes
- **yara-analyzer**: YARA rule matching (optional)
- **capa-analyzer**: Capability extraction (optional)

#### CLI
- Interactive console with commands: help, version, upload, status, report, jobs
- Environment-based configuration

#### Observability
- Structured JSON logging
- Prometheus metrics endpoint
- Health and readiness probes

#### Security
- Container isolation (no network, read-only rootfs, dropped capabilities)
- Audit logging with completeness
- Output sanitization

#### Infrastructure
- Docker Compose for local development
- Kubernetes manifests for production deployment
- Alembic migrations for database schema

### Changed
- None (initial release)

### Deprecated
- None

### Removed
- None

### Fixed
- None (initial release)

### Security
- Default passwords must be changed in production
- Docker socket access required for worker (consider alternatives for production)

## [Unreleased]

### Planned
- Full OIDC integration
- Additional analyzer types
- Enhanced retention policies
- OpenTelemetry tracing
