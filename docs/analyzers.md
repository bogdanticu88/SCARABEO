# SCARABEO Analyzers

## Overview

SCARABEO includes multiple static analyzers that run in isolated Docker containers. Each analyzer produces partial outputs that are merged into a final report.

## Available Analyzers

| Analyzer | File Types | Description |
|----------|------------|-------------|
| `triage-universal` | All | Strings, entropy, IOC extraction, basic findings |
| `pe-analyzer` | PE/EXE/DLL | PE header parsing, imports, sections, packer detection |
| `elf-analyzer` | ELF | ELF headers, sections, suspicious functions, RPATH |
| `script-analyzer` | Scripts | PS1, VBS, JS, SH, PY - obfuscation detection, IOCs |
| `doc-analyzer` | Documents | OLE/OOXML - macros, embedded objects, external links |
| `archive-analyzer` | Archives | ZIP, 7z, RAR - safe listing, controlled extraction |
| `similarity-analyzer` | All | SSDEEP, TLSH, imphash for similarity matching |
| `yara-analyzer` | All | YARA rule matching (optional, feature flag) |
| `capa-analyzer` | PE/ELF | Capability extraction (optional, feature flag) |

## Pipeline Recipes

### triage
Fast basic analysis for all file types.
- `triage-universal`
- `similarity-analyzer`

### deep
Comprehensive analysis with file-type specific analyzers.
- `triage-universal`
- File-type analyzer (pe/elf/script/doc/archive)
- `similarity-analyzer`
- `yara-analyzer` (if enabled)
- `capa-analyzer` (if enabled)

### archive
Archive handling with child job support.
- `triage-universal`
- `archive-analyzer`
- Spawns child jobs for extracted executables

## Feature Flags

| Flag | Analyzer | Default |
|------|----------|---------|
| `YARA_ENABLED` | yara-analyzer | false |
| `CAPA_ENABLED` | capa-analyzer | false |
| `ARCHIVE_EXTRACT` | archive-analyzer | false |
| `SEVENZ_SUPPORT` | archive-analyzer | false |
| `RAR_SUPPORT` | archive-analyzer | false |

## Analyzer Output

All analyzers produce partial outputs conforming to `contracts/schemas/partial.schema.json`:

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

## Building Analyzer Images

```bash
# Build all analyzer images
make build-analyzers

# Build specific analyzer
docker build -t scarabeo/pe-analyzer:latest -f analyzers/pe-analyzer/Dockerfile analyzers/pe-analyzer/
```

## Adding a New Analyzer

1. Create `analyzers/<name>/` directory
2. Add `analyzer.py` with analysis logic
3. Add `Dockerfile` based on Python slim
4. Register in `services/worker/router.py`
5. Add to pipeline recipes
6. Write tests

## Determinism

All analyzers guarantee deterministic output:
- Sorted findings by id
- Sorted IOCs by type, then value
- Sorted artifacts by path
- No random values or timestamps from system clock
