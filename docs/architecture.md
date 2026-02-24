# Scarabeo Architecture

## Overview

Scarabeo is a modular malware analysis framework designed for scalability, reproducibility, and security. The system follows a microservices architecture with clear separation of concerns between ingestion, orchestration, analysis, and reporting.

## System Components

### Services

#### API Service (`services/api/`)
- RESTful HTTP interface for sample submission and result retrieval
- Authentication and rate limiting
- Request validation against JSON schemas
- Async job queue integration

#### Ingest Service (`services/ingest/`)
- Sample intake and validation
- File type detection and hashing (MD5, SHA1, SHA256, SHA512, SSDEEP, TLSH)
- Object storage integration (MinIO/S3)
- Deduplication logic

#### Orchestrator Service (`services/orchestrator/`)
- Pipeline execution coordination
- Engine scheduling and resource management
- Timeout and failure handling
- Result aggregation

#### Worker Service (`services/worker/`)
- Analysis engine execution in isolated environments
- Artifact collection and storage
- Real-time progress reporting
- Container lifecycle management

### Analyzers

Analyzers are modular components that perform specific analysis tasks. Each analyzer:

1. Receives input via `input.json` in its work directory
2. Produces output to `/work/out/report.json`
3. Stores artifacts in `/work/out/artifacts/`

#### Analyzer Contract

```
/work/
├── in/
│   └── input.json          # Analysis input (conforming to input.schema.json)
├── out/
│   ├── report.json         # Analysis results (conforming to report.schema.json)
│   └── artifacts/          # Generated artifacts
│       ├── screenshot_001.png
│       ├── capture.pcap
│       └── ...
└── sample/                 # The sample being analyzed (read-only)
```

#### Built-in Analyzers

| Analyzer | Type | Description |
|----------|------|-------------|
| `static` | Static | PE/ELF/Mach-O analysis, strings, imports, sections |
| `dynamic` | Dynamic | Behavioral analysis in sandboxed VM |
| `unpacker` | Static | Automatic unpacking of packed executables |
| `config` | Static | Malware configuration extraction |
| `yara` | Static | YARA rule matching |
| `sandbox` | Dynamic | Full system sandbox with hooking |

## Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│     API     │────▶│    Ingest   │
└─────────────┘     └─────────────┘     └─────────────┘
                                              │
                                              ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │◀────│     API     │◀────│  Orchestrator│
└─────────────┘     └─────────────┘     └─────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
            ┌───────────────┐         ┌───────────────┐         ┌───────────────┐
            │   Worker 1    │         │   Worker 2    │         │   Worker N    │
            │  (Analyzer)   │         │  (Analyzer)   │         │  (Analyzer)   │
            └───────────────┘         └───────────────┘         └───────────────┘
```

### Flow Description

1. **Submission**: Client uploads sample via `POST /samples`
2. **Ingestion**: 
   - Sample is hashed and stored in object storage
   - Metadata is recorded in PostgreSQL
   - Analysis job is queued in Redis
3. **Orchestration**:
   - Orchestrator picks up job from queue
   - Determines which analyzers to run based on file type and options
   - Spawns workers with isolated environments
4. **Analysis**:
   - Workers execute analyzers in containers
   - Analyzers read `input.json`, process sample, write `report.json`
   - Artifacts are uploaded to object storage
5. **Aggregation**:
   - Orchestrator collects results from all workers
   - Merges findings, IOCs, and artifacts
   - Generates final report conforming to `report.schema.json`
6. **Retrieval**: Client fetches results via `GET /samples/{sha256}/report`

### Schema Validation

Schema validation is enforced at runtime in the worker pipeline. Before any
partial outputs are merged, each partial is validated against
`contracts/schemas/partial.schema.json`. After merging, the assembled report
is validated against `contracts/schemas/report.schema.json`. Both checks use
`jsonschema.Draft202012Validator`.

If validation fails, the job is marked `FAILED` immediately with an error
message that identifies:
- Which schema failed (`partial` or `report`)
- Which analyzer produced the invalid output (for partials)
- The exact JSON path of the violation
- The jsonschema error message

This is a fail-closed design: no invalid report is stored.

## Storage

### PostgreSQL
- Sample metadata and analysis history
- Tenant configuration and quotas
- User and API key management
- Job queue state

### Redis
- Task queue (Celery broker)
- Result backend
- Caching layer
- Real-time progress updates (pub/sub)

### MinIO (S3-compatible)
- Sample storage (immutable, content-addressed)
- Artifact storage
- Report archives

## Pipeline Configuration

Pipelines define the sequence of analyzers to run:

```yaml
pipeline:
  name: full-analysis
  version: "1.0"
  stages:
    - name: static
      engines: [yara, static, config]
      parallel: true
    - name: dynamic
      engines: [sandbox]
      parallel: false
      condition: "static.score > 30"
    - name: unpack
      engines: [unpacker]
      parallel: false
      condition: "static.packed == true"
```

## Message Formats

All inter-service communication uses JSON messages conforming to schemas in `contracts/schemas/`:

- `input.schema.json` - Analysis request format
- `report.schema.json` - Complete analysis report
- `finding.schema.json` - Individual security finding
- `ioc.schema.json` - Indicator of compromise
- `artifact.schema.json` - Generated artifact metadata
- `provenance.schema.json` - Reproducibility metadata

## Extension Points

### Adding a New Analyzer

1. Create analyzer directory under `analyzers/`
2. Implement `analyze(input.json) -> report.json` interface
3. Define analyzer metadata in `analyzer.yaml`
4. Register analyzer in orchestrator configuration

### Adding a New Engine

1. Implement engine class with `run(sample_path, options) -> dict` interface
2. Engine must produce findings conforming to `finding.schema.json`
3. Register engine in service configuration

## Deployment

See `infra/docker-compose.yml` for local development setup. Production deployments should use Kubernetes with:

- Horizontal Pod Autoscaler for workers
- PodDisruptionBudget for high availability
- NetworkPolicies for isolation
- PodSecurityPolicies for container hardening
