# Pipeline and Analyzer Architecture

## Overview

Scarabeo uses a modular analyzer architecture where each analyzer runs in an isolated Docker container and produces partial outputs that are merged into a final report by the worker.

## Analyzer Interface

### Input Contract

All analyzers receive the same input format via `/work/input.json`:

```json
{
  "schema_version": "1.0.0",
  "sample_sha256": "<sha256 hash>",
  "tenant_id": "<tenant>",
  "sample": {
    "filename": "<original filename>",
    "size_bytes": <size>,
    "storage_path": "<S3 path>"
  },
  "options": {
    "timeout_seconds": 300,
    "engines": ["analyzer-name"],
    "priority": "normal"
  },
  "metadata": {
    "pipeline_name": "deep",
    "pipeline_hash": "<hash>",
    "file_type": "pe"
  }
}
```

### Output Contract (Partial)

Analyzers produce partial outputs to `/work/out/partial.json`:

```json
{
  "schema_version": "1.0.0",
  "analyzer_name": "pe-analyzer",
  "analyzer_version": "0.1.0",
  "findings": [...],
  "iocs": [...],
  "artifacts": [...],
  "metadata": {...}
}
```

**Alternative:** Analyzers can produce a full `report.json` if they are the only analyzer or if they perform complete analysis.

### Merge Approach

The worker uses **partial output merging** (preferred approach):

1. Each analyzer produces `partial.json` with its findings, IOCs, and artifacts
2. Worker merges all partial outputs into final `report.json`
3. Merge is deterministic: sorted by analyzer name, then by finding/ioc/artifact id
4. Before merging, each partial is validated against `contracts/schemas/partial.schema.json`.
   After merging, the final report is validated against `contracts/schemas/report.schema.json`.
   Validation failures abort the job with a descriptive error (schema name, field path, reason).
   Schema validation is enforced at runtime — analyzers that produce non-conforming output
   will cause the job to fail.

## Analyzer Routing

The worker routes analyzers based on:

| file_type | Analyzers Run |
|-----------|---------------|
| `pe` | triage-universal, pe-analyzer, similarity-analyzer, (yara-analyzer if enabled) |
| `elf` | triage-universal, elf-analyzer, similarity-analyzer |
| `macho` | triage-universal, similarity-analyzer |
| `script` | triage-universal, script-analyzer, similarity-analyzer |
| `document` | triage-universal, doc-analyzer, similarity-analyzer |
| `archive` | triage-universal, archive-analyzer (may spawn child jobs) |
| `unknown` | triage-universal, similarity-analyzer |

## Pipeline Recipes

### triage.yaml

Basic static analysis for all file types:
- triage-universal (strings, entropy, IOC extraction)

### deep.yaml

Comprehensive analysis:
- triage-universal
- File-type specific analyzer (pe/elf/script/doc)
- similarity-analyzer
- yara-analyzer (optional, feature flag)
- capa-analyzer (optional, feature flag)

### archive.yaml

Archive handling with recursion:
- triage-universal
- archive-analyzer
- Spawns child jobs for extracted executables

## Feature Flags

| Flag | Analyzer | Description |
|------|----------|-------------|
| `YARA_ENABLED` | yara-analyzer | Enable YARA rule matching |
| `CAPA_ENABLED` | capa-analyzer | Enable capability extraction |
| `ARCHIVE_EXTRACT` | archive-analyzer | Enable actual extraction (vs listing only) |
| `SEVENZ_SUPPORT` | archive-analyzer | Enable 7z archive support |
| `RAR_SUPPORT` | archive-analyzer | Enable RAR archive support |

## Determinism Guarantees

All analyzers must:

1. Sort findings by id
2. Sort IOCs by type, then value
3. Sort artifacts by path
4. Use deterministic timestamps (from input or analysis_start)
5. Not use random values or non-deterministic algorithms

## Adding a New Analyzer

1. Create `analyzers/<name>/` directory
2. Add `Dockerfile` with Python base image
3. Implement analyzer reading `/work/input.json` and writing `/work/out/partial.json`
4. Validate output against `partial.schema.json`
5. Add to worker router in `services/worker/router.py`
6. Add to pipeline recipes as needed
7. Write unit tests

## Artifact Storage

Artifacts are stored in S3 under:
```
samples/{tenant_id}/{sha256}/artifacts/{pipeline_hash}/{analyzer_name}/{filename}
```

## Child Job Linking

For archives that spawn child jobs, relationships are tracked in the `sample_relations` table:

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `parent_sha256` | String(64) | Parent sample hash |
| `child_sha256` | String(64) | Child sample hash |
| `relationship` | String | Type: "extracted_from_archive", "dropped_by_pe", etc. |
| `metadata` | JSON | Additional context |
| `created_at` | DateTime | Creation timestamp |
