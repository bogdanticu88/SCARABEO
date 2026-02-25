# Evasion Detection Engine

`scarabeo/evasion.py` is a static heuristics library that analyses Windows PE
binaries for evasion, injection, persistence, and C2-related signals. It
produces a structured `EvasionProfile` containing categorised indicators and an
aggregate score (0–100).

---

## Signal Sources

The engine accepts three independent input sources. Each source can be used on
its own or combined.

### 1. Import Table (`imports`)

A list of PE import records, each with the DLL name and the list of imported
function names:

```python
imports = [
    {"dll": "kernel32.dll", "functions": ["VirtualAllocEx", "WriteProcessMemory"]},
    {"dll": "ntdll.dll",    "functions": ["NtCreateThreadEx"]},
]
```

The engine walks `_IMPORT_TABLE` — a dict keyed by lowercase DLL name — and
matches each function against technique-specific function lists. One
`EvasionIndicator` is emitted per matched technique, with `source="imports"`.

### 2. Extracted Strings (`strings`)

A list of printable strings extracted from the binary (ASCII / UTF-16LE):

```python
strings = [
    "vmtoolsd.exe",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "cmd.exe /c whoami",
]
```

The engine walks `_STRING_PATTERNS` — a dict keyed by `category.technique` —
and performs case-insensitive substring matching. One `EvasionIndicator` is
emitted per matched pattern group, with `source="strings"`.

### 3. PE Header Metadata (`metadata`)

A dict populated from the parsed PE optional header and section table:

```python
metadata = {
    "dll_characteristics": 0x0100,   # WORD from PE optional header at +70
    "sections": [
        {"name": ".text", "entropy": 7.8, "raw_size": 4096, "characteristics": 0xE0000000},
    ],
    "packers":           ["upx"],    # from section name matching
    "timestamp_anomaly": {"type": "zero_timestamp", "description": "..."},
    "import_count":      2,          # total imported functions
    "subsystem_code":    3,          # 2=GUI, 3=CUI, 9=WinCE
}
```

Metadata analysis is only performed when `metadata is not None`. It emits
indicators with `source="metadata"`.

---

## Categories, Severity, and Base Scores

| Category          | Severity | Base Score | Description |
|-------------------|----------|-----------|-------------|
| `anti_debug`      | MEDIUM   | 12        | Debugger detection and interference |
| `anti_vm`         | MEDIUM   | 15        | Virtual machine environment detection |
| `anti_sandbox`    | HIGH     | 18        | Sandbox / analysis tool detection |
| `injection`       | HIGH     | 25        | Process / memory injection primitives |
| `privesc`         | HIGH     | 20        | Privilege escalation APIs |
| `persistence`     | HIGH     | 18        | Persistence mechanisms |
| `credential_access` | HIGH   | 15        | Cryptographic / credential APIs |
| `network`         | MEDIUM   | 10        | Network and C2 communication |
| `packer`          | MEDIUM   | 10        | Runtime packing / unpacking |
| `stealth`         | HIGH     | 20        | Rootkit / DKOM string indicators |
| `anti_forensics`  | MEDIUM   | 12        | PE header manipulation signals |

---

## Technique Reference

### Import-Based Techniques

| Technique | DLL | Key Functions |
|-----------|-----|--------------|
| `anti_debug.debugger_presence` | kernel32 | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` |
| `anti_debug.timing_check` | kernel32 | `GetTickCount`, `QueryPerformanceCounter` |
| `anti_debug.nt_query` | ntdll | `NtQueryInformationProcess`, `ZwQueryInformationProcess` |
| `anti_debug.thread_hiding` | ntdll | `NtSetInformationThread` |
| `anti_debug.hook_install` | user32 | `SetWindowsHookExA/W` |
| `anti_sandbox.window_check` | user32 | `GetForegroundWindow`, `FindWindowA/W` |
| `anti_sandbox.input_state` | user32 | `GetAsyncKeyState`, `BlockInput` |
| `injection.memory_ops` | kernel32 | `VirtualAllocEx`, `WriteProcessMemory` |
| `injection.thread_creation` | kernel32 | `CreateRemoteThread`, `QueueUserAPC` |
| `injection.process_hollowing` | kernel32/ntdll/shell32 | `CreateProcess`, `NtUnmapViewOfSection`, `ShellExecuteA/W` |
| `injection.nt_thread` | ntdll | `NtCreateThreadEx`, `RtlCreateUserThread` |
| `injection.nt_memory` | ntdll | `NtWriteVirtualMemory`, `NtAllocateVirtualMemory` |
| `injection.dll_load` | kernel32 | `LoadLibraryA/W` |
| `injection.function_resolution` | kernel32/msvcrt | `GetProcAddress`, `system` |
| `privesc.token_manipulation` | advapi32 | `AdjustTokenPrivileges`, `ImpersonateLoggedOnUser` |
| `privesc.privilege_lookup` | advapi32 | `LookupPrivilegeValueA/W` |
| `persistence.registry_write` | advapi32 | `RegSetValueExA/W`, `RegCreateKeyExA/W` |
| `persistence.service_install` | advapi32 | `OpenSCManagerA/W`, `CreateServiceA/W` |
| `credential_access.crypto` | advapi32 | `CryptEncrypt`, `CryptAcquireContextA/W` |
| `network.socket_ops` | ws2_32 | `socket`, `connect`, `send`, `recv` |
| `network.name_resolution` | ws2_32 | `gethostbyname`, `getaddrinfo` |
| `network.http_client` | winhttp/wininet | `WinHttpOpen`, `InternetOpenA/W` |
| `packer.decompression` | ntdll | `RtlDecompressBuffer` |

### String-Based Techniques

| Technique | Example Strings |
|-----------|----------------|
| `anti_vm.vm_artifacts` | `vmtoolsd.exe`, `vboxservice.exe`, `qemu`, `kvmkvmkvm` |
| `anti_vm.vm_registry` | `software\vmware, inc.`, `software\oracle\virtualbox` |
| `anti_sandbox.sandbox_artifacts` | `cuckoomon`, `wireshark.exe`, `c:\analysis`, `joesandbox` |
| `anti_debug.string_indicators` | `ntglobalflag`, `heap flags`, `beingdebugged` |
| `anti_debug.debugger_names` | `ollydbg`, `x64dbg`, `windbg`, `ida pro` |
| `privesc.privilege_strings` | `SeDebugPrivilege`, `SeImpersonatePrivilege` |
| `persistence.autorun_keys` | `software\microsoft\windows\currentversion\run` |
| `stealth.rootkit_strings` | `\Device\PhysicalMemory`, `DKOM` |
| `network.c2_patterns` | `cmd.exe /c`, `powershell -encodedcommand`, `certutil -urlcache` |

### Metadata-Based Techniques

| Technique | Condition | Notes |
|-----------|-----------|-------|
| `anti_forensics.aslr_disabled` | `DYNAMIC_BASE` (0x0040) not set | User-mode only |
| `injection.dep_disabled` | `NX_COMPAT` (0x0100) not set | User-mode only |
| `anti_debug.seh_disabled` | `NO_SEH` (0x0800) set | Any subsystem |
| `anti_forensics.timestamp_anomaly` | Zero, future, or pre-1990 timestamp | |
| `packer.section_names` | Packer name in section name list | UPX, Themida, VMProtect, … |
| `packer.high_entropy` | Any section with entropy > 7.0 and raw_size > 0 | |
| `injection.rwx_section` | Section with Execute + Read + Write characteristics | |
| `anti_debug.minimal_imports` | `import_count < 3`, user-mode, no known packer | |

---

## Scoring Algorithm

The composite score is computed in `_compute_score_detailed()`.

### Step 1 — Category grouping

All indicators are grouped by `category`. Multiple techniques within the same
category give diminishing returns; they contribute less than simply adding their
base scores:

```
contribution(category) = base_score × (1 − 0.7^n) / (1 − 0.7)
```

where `n` is the number of distinct techniques fired in that category. A single
technique contributes the full base score. Each additional technique adds 70% of
the previous contribution, asymptotically approaching `base_score / 0.3`.

**Example — injection category (base = 25):**

| Techniques fired | Contribution |
|-----------------|-------------|
| 1 | 25 |
| 2 | 42 |
| 3 | 55 |
| 4 | 63 |

### Step 2 — Summation and cap

Category contributions are summed and capped at 100:

```
score = min(sum(contribution per category), 100)
```

### Step 3 — Score breakdown

The `EvasionProfile.score_breakdown` field holds the per-category integer
contribution, useful for explaining why a sample received a particular score:

```python
profile.score_breakdown
# {'injection': 42, 'anti_debug': 12, 'network': 10, 'persistence': 18}
```

### Confidence

Each indicator carries a `confidence` value (50–95) computed from how many
functions / strings within a technique's expected set actually matched:

```
confidence = 50 + 45 × (1 − e^(−3 × matched/total))
```

- 1 match out of many → ~60
- Half the set matched → ~75
- All matched → ~90–95

For metadata indicators, confidence is assigned statically (65–90) based on
signal strength.

---

## Integration

### pe-analyzer

`analyzers/pe-analyzer/analyzer.py` calls the full three-source pipeline:

1. **Imports** — extracted from the Import Directory Table
2. **Strings** — extracted from raw bytes via `extract_strings_from_binary()`
   (printable ASCII, min 4 chars, capped at 5000 strings)
3. **Metadata** — built from `parse_pe_header()` output:
   - `dll_characteristics` (parsed from optional header at offset +70)
   - `sections` (section table with entropy and characteristic flags)
   - `packers` (from `detect_packer()`)
   - `timestamp_anomaly` (from `check_timestamp_anomaly()`)
   - `import_count` (total functions imported across all DLLs)
   - `subsystem_code`

Evasion findings are merged with structural PE findings and sorted by ID before
being written to the partial output.

The `pe_summary` artifact includes:
- `evasion_score` — aggregate score (0–100)
- `evasion_score_breakdown` — per-category contributions
- `evasion_categories` — sorted list of triggered categories

### triage-universal

`analyzers/triage-universal/analyzer.py` runs evasion on the extracted string
list only (`imports=[]`, `metadata=None`). This catches any file type that
contains Windows PE indicator strings (e.g., a script dropper or a packed
archive containing a PE).

Evasion findings are merged into the standard findings list and the evasion
score contributes to the verdict:

```
effective_score = max(structural_score, evasion_score)
```

The `summary` block in the report includes:
- `evasion_score`
- `evasion_categories`

---

## Usage Example

```python
from scarabeo.evasion import build_evasion_profile, evasion_profile_to_findings

imports = [
    {"dll": "kernel32.dll", "functions": ["VirtualAllocEx", "CreateRemoteThread"]},
    {"dll": "advapi32.dll", "functions": ["RegSetValueExA", "AdjustTokenPrivileges"]},
]
strings = ["vmtoolsd.exe", "cmd.exe /c whoami"]
metadata = {
    "dll_characteristics": 0x0100,   # ASLR disabled
    "sections":            [{"name": ".text", "entropy": 7.9, "raw_size": 8192,
                             "characteristics": 0xE0000000}],
    "packers":             [],
    "timestamp_anomaly":   None,
    "import_count":        10,
    "subsystem_code":      3,
}

profile = build_evasion_profile(imports=imports, strings=strings, metadata=metadata)

print(f"Score: {profile.score}")
print(f"Breakdown: {profile.score_breakdown}")
print(f"Has injection: {profile.has_injection}")
print(f"Has anti-VM: {profile.has_anti_vm}")

findings = evasion_profile_to_findings(profile, source="my-analyzer")
for f in findings:
    print(f"[{f['severity']}] {f['id']}: {f['title']}")
```

---

## Extending the Engine

### Adding import-based rules

Add an entry to `_IMPORT_TABLE` under the appropriate DLL:

```python
"ntdll.dll": {
    ...
    "injection.atom_bombing": [
        "NtQueueApcThread", "GlobalAddAtomA",
    ],
},
```

Add a title entry to `_technique_title()` and a reference to
`_technique_references()`.

### Adding string patterns

Add a list of case-insensitive substrings to `_STRING_PATTERNS`:

```python
"anti_vm.vm_artifacts": [
    ...
    "hyperv_is_running",
],
```

### Adding metadata rules

Extend `analyze_metadata()` with additional checks against `pe_meta`. Use an
existing category or add a new one to `_CATEGORY_SEVERITY` and
`_CATEGORY_SCORES`.
