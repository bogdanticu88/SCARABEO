# SCARABEO Analyzers

## Overview

SCARABEO includes multiple static analyzers that run in isolated Docker containers.
Each analyzer receives `/work/input.json`, reads the sample from `/work/sample`,
and writes `/work/output/report.json` (a `partial.schema.json`-conforming dict)
plus any supporting artifacts under `/work/output/artifacts/`.

## Available Analyzers

| Analyzer | File Types | Description |
|----------|------------|-------------|
| `triage-universal` | All | Strings, entropy, IOC extraction, file type detection |
| `pe-analyzer` | PE/EXE/DLL | PE header, real import table, section anomalies, packer detection |
| `elf-analyzer` | ELF | ELF headers, sections, suspicious functions, RPATH |
| `script-analyzer` | Scripts | PS1, VBS, JS, SH, PY — obfuscation detection, IOCs |
| `doc-analyzer` | Documents | OLE/OOXML — macros, embedded objects, external links |
| `archive-analyzer` | Archives | ZIP, 7z, RAR — safe listing, controlled extraction |
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
- `yara-analyzer` (if `YARA_ENABLED`)
- `capa-analyzer` (if `CAPA_ENABLED`)

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

---

## triage-universal

Runs on every file regardless of type. Produces hashes, entropy, extracted
strings, and network/email IOCs.

### File type detection

`detect_file_type(data, filename)` inspects magic bytes to classify the sample
before returning the report. Supported types: `pe`, `elf`, `archive`,
`document`, `script`, `unknown`. If magic bytes are ambiguous, the filename
extension is used as a fallback. The result is emitted as `file_type` in the
report and is consumed by the worker router to select the correct deep-analysis
pipeline.

### Output fields (in `report.json`)

| Field | Description |
|-------|-------------|
| `file_type` | Detected file type string |
| `avg_entropy` | Mean Shannon entropy across 4 KB chunks |
| `hashes` | md5, sha1, sha256, sha512 |
| `findings` | High-entropy, network IOC, email IOC findings |
| `iocs` | Normalized URL, domain, IP, email records |
| `artifacts[0]` | `artifacts/strings.txt` — extracted ASCII + UTF-16LE strings |

### Docker image

```
scarabeo/triage-universal:latest
```

Built from `analyzers/triage-universal/Dockerfile`.

---

## pe-analyzer

Deep static analysis of Windows PE files (EXE, DLL, SYS).

### Import Directory Table parsing

`parse_import_directory()` walks the real Import Directory (IID array at the
RVA in the Optional Header's data directory slot 1). For each
`IMAGE_IMPORT_DESCRIPTOR` it reads:

- The DLL name via the Name RVA
- Each thunk from the Import Name Table (INT/OriginalFirstThunk)
- For by-name imports: the function name from `IMAGE_IMPORT_BY_NAME.Name`
- For by-ordinal imports: recorded as `#N`

Supports both PE32 (32-bit, DWORD thunks) and PE32+ (64-bit, QWORD thunks).

### Section anomaly detection

`detect_section_anomalies()` flags two classes of anomalies:

| Type | Condition | Severity |
|------|-----------|----------|
| `rwx` | Section has Execute + Read + Write characteristics | HIGH |
| `vsize_inflation` | `virtual_size > raw_size × 4` | MEDIUM |

RWX sections indicate runtime code modification (shellcode staging, unpacking
stubs). Virtual size inflation indicates that the loader will map a much larger
region than exists on disk, a common unpacking technique.

### Packer detection

`detect_packer()` matches section names (case-insensitive) against a table of
known signatures:

| Section Name | Packer |
|--------------|--------|
| UPX0, UPX1, UPX! | upx |
| .aspack, .adata | aspack |
| .themida | themida |
| .vmp0, .vmp1 | vmprotect |
| .petite | petite |
| .MPRESS1, .MPRESS2 | mpress |

### Suspicious import detection

`detect_suspicious_imports()` checks resolved function names against a per-DLL
allowlist of high-risk APIs (e.g. `VirtualAlloc`, `CreateRemoteThread`,
`NtCreateThreadEx`, `WinHttpOpen`). One finding is emitted per flagged DLL.

### Stable finding IDs

All finding IDs are derived from content, not execution order:

| Pattern | Example |
|---------|---------|
| `pe-packer-{name}` | `pe-packer-upx` |
| `pe-entropy-sections` | fixed (one finding lists all high-entropy sections) |
| `pe-imports-suspicious-{dll_stem}` | `pe-imports-suspicious-kernel32` |
| `pe-section-rwx-{section}` | `pe-section-rwx-bad` |
| `pe-section-vsize_inflation-{section}` | `pe-section-vsize_inflation-unpack` |
| `pe-timestamp-{type}` | `pe-timestamp-zero_timestamp` |
| `pe-gui-no-resources` | fixed |

Re-running the analyzer on the same binary produces identical finding IDs.

### Artifacts produced

| Path | Type | Description |
|------|------|-------------|
| `artifacts/pe_summary.json` | `pe_summary` | Full PE metadata (sections, imports, packers) |
| `artifacts/imports.txt` | `imports` | Per-DLL import lists, sorted |

Both artifacts include `sha256` and `size_bytes` in the partial output.

### Testable entry point

`analyze_pe_bytes(data: bytes, sha256: str) -> dict` takes raw PE bytes and
returns the partial dict without any filesystem access. All unit tests in
`tests/test_pe_analyzer.py` call this function directly via in-memory PE
binaries constructed by `_build_pe()` and `_build_idata()`.

### Docker image

```
scarabeo/pe-analyzer:latest
```

Built from `analyzers/pe-analyzer/Dockerfile`:

```bash
# Build
docker build -t scarabeo/pe-analyzer:latest \
  -f analyzers/pe-analyzer/Dockerfile \
  analyzers/pe-analyzer/

# Invocation (handled by docker_executor.py)
docker run --rm \
  --read-only \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -v /host/input.json:/work/input.json:ro \
  -v /host/sample:/work/sample:ro \
  -v /host/output:/work/output \
  scarabeo/pe-analyzer:latest
```

Input: `/work/input.json` — JSON with `sample_sha256`, `tenant_id`, `metadata`.
Output: `/work/output/report.json` — partial.schema.json dict.
Artifacts: `/work/output/artifacts/pe_summary.json`, `imports.txt`.

---

## Analyzer Output Format

All analyzers produce partial outputs conforming to `contracts/schemas/partial.schema.json`:

```json
{
  "schema_version": "1.0.0",
  "analyzer_name": "pe-analyzer",
  "analyzer_version": "0.1.0",
  "findings": [...],
  "iocs": [...],
  "artifacts": [...],
  "metadata": {}
}
```

The worker validates each partial against the schema before merging. Invalid
partials cause the job to fail immediately (fail-closed).

## Building Analyzer Images

```bash
# Build all analyzer images
make build-analyzers

# Build specific analyzer
docker build -t scarabeo/pe-analyzer:latest \
  -f analyzers/pe-analyzer/Dockerfile \
  analyzers/pe-analyzer/

docker build -t scarabeo/triage-universal:latest \
  -f analyzers/triage-universal/Dockerfile \
  analyzers/triage-universal/
```

## Adding a New Analyzer

1. Create `analyzers/<name>/` directory
2. Add `analyzer.py` with analysis logic; expose a pure `analyze_<type>_bytes(data, sha256) -> dict` function for testability
3. Add `Dockerfile` — ensure `RUN mkdir -p /work/output/artifacts`
4. Register in `services/worker/router.py`
5. Add to pipeline recipes
6. Write tests using in-memory data (no real samples needed)

## Determinism

All analyzers guarantee deterministic output:
- Findings sorted by id (content-derived, not counter-based)
- IOCs sorted by type, then value
- Artifacts sorted by path
- No random values or timestamps from system clock in finding IDs
