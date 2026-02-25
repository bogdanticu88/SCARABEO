"""Static evasion heuristics for Windows PE samples.

Analyses three input sources:
    imports  — list of {"dll": str, "functions": [str, ...]} records from
               the PE Import Directory Table
    strings  — list of printable strings extracted from the binary
    metadata — optional PE header / section-table signals (DllCharacteristics,
               section entropy/characteristics, packer names, timestamp anomaly)

Produces an EvasionProfile containing categorized EvasionIndicators and an
aggregate score (0–100) plus a per-category score breakdown.

Public API
----------
analyze_imports(imports)              -> list[EvasionIndicator]
analyze_strings(strings)              -> list[EvasionIndicator]
analyze_metadata(pe_meta)             -> list[EvasionIndicator]
build_evasion_profile(imports, strings, metadata) -> EvasionProfile
compute_score(indicators)             -> int
evasion_profile_to_findings(profile, source) -> list[dict]
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

# ── PE section characteristic flags (used by analyze_metadata) ─────────────
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ    = 0x40000000
_SCN_MEM_WRITE   = 0x80000000
_SCN_RWX_MASK    = _SCN_MEM_EXECUTE | _SCN_MEM_READ | _SCN_MEM_WRITE

# ── PE DllCharacteristics flags ─────────────────────────────────────────────
_DLLCHAR_DYNAMIC_BASE = 0x0040   # ASLR enabled
_DLLCHAR_NX_COMPAT    = 0x0100   # DEP/NX enabled
_DLLCHAR_NO_SEH       = 0x0800   # no structured exception handling

# Subsystem codes for user-mode processes
_USERMODE_SUBSYSTEMS = frozenset({2, 3, 9})   # Windows GUI, Windows CUI, WinCE GUI

# Per-section entropy threshold above which a section is considered packed
_HIGH_ENTROPY_THRESHOLD = 7.0

# Fewer than this many imported functions in a user-mode EXE is suspicious
_MINIMAL_IMPORT_THRESHOLD = 3


# ── Import-based indicator tables ────────────────────────────────────────────
#
# Structure: { dll_name: { technique_id: [function_names] } }
# dll_name is lowercase.  technique_id becomes part of the indicator key.

_IMPORT_TABLE: dict[str, dict[str, list[str]]] = {
    "kernel32.dll": {
        # Anti-debug
        "anti_debug.debugger_presence": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "DebugBreak", "OutputDebugStringA", "OutputDebugStringW",
        ],
        "anti_debug.timing_check": [
            "GetTickCount", "GetTickCount64",
            "QueryPerformanceCounter", "QueryPerformanceFrequency",
            "timeGetTime",
        ],
        # Process injection
        "injection.memory_ops": [
            "VirtualAllocEx", "VirtualProtectEx",
            "WriteProcessMemory", "ReadProcessMemory",
        ],
        "injection.thread_creation": [
            "CreateRemoteThread", "CreateRemoteThreadEx",
            "QueueUserAPC",
        ],
        "injection.process_hollowing": [
            "CreateProcess", "CreateProcessA", "CreateProcessW",
            "ResumeThread", "SuspendThread",
        ],
        "injection.process_enumeration": [
            "CreateToolhelp32Snapshot", "Process32First", "Process32FirstW",
            "Process32Next", "Process32NextW",
            "Module32First", "Module32Next",
        ],
        # DLL injection / hook
        "injection.dll_load": [
            "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        ],
        "injection.function_resolution": [
            "GetProcAddress",
        ],
        # Persistence
        "persistence.file_ops": [
            "CopyFile", "CopyFileA", "CopyFileW",
            "MoveFile", "MoveFileA", "MoveFileW",
            "DeleteFile", "DeleteFileA", "DeleteFileW",
        ],
    },
    "ntdll.dll": {
        # Anti-debug
        "anti_debug.nt_query": [
            "NtQueryInformationProcess",
            "RtlQueryProcessDebugInformation",
            "ZwQueryInformationProcess",
        ],
        "anti_debug.thread_hiding": [
            "NtSetInformationThread", "ZwSetInformationThread",
        ],
        # Process injection (native API)
        "injection.nt_memory": [
            "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
            "NtProtectVirtualMemory", "ZwProtectVirtualMemory",
            "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory",
        ],
        "injection.nt_thread": [
            "NtCreateThread", "NtCreateThreadEx",
            "ZwCreateThread", "ZwCreateThreadEx",
            "RtlCreateUserThread",
        ],
        "injection.process_hollowing": [
            "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        ],
        # Decompression (often used by packers)
        "packer.decompression": [
            "RtlDecompressBuffer", "RtlDecompressFragment",
        ],
    },
    "advapi32.dll": {
        # Privilege escalation
        "privesc.token_manipulation": [
            "AdjustTokenPrivileges",
            "OpenProcessToken", "OpenThreadToken",
            "ImpersonateLoggedOnUser", "DuplicateTokenEx",
        ],
        "privesc.privilege_lookup": [
            "LookupPrivilegeValueA", "LookupPrivilegeValueW",
            "LookupPrivilegeNameA", "LookupPrivilegeNameW",
        ],
        # Persistence (registry)
        "persistence.registry_write": [
            "RegSetValueA", "RegSetValueW",
            "RegSetValueExA", "RegSetValueExW",
            "RegCreateKeyA", "RegCreateKeyW",
            "RegCreateKeyExA", "RegCreateKeyExW",
        ],
        # Persistence (services)
        "persistence.service_install": [
            "OpenSCManagerA", "OpenSCManagerW",
            "CreateServiceA", "CreateServiceW",
            "StartServiceA", "StartServiceW",
        ],
        # Credential access
        "credential_access.crypto": [
            "CryptEncrypt", "CryptDecrypt",
            "CryptGenKey", "CryptAcquireContextA", "CryptAcquireContextW",
            "CryptHashData", "CryptDeriveKey",
        ],
    },
    "user32.dll": {
        # Anti-sandbox (window / UI-state checks)
        "anti_sandbox.window_check": [
            "GetForegroundWindow", "FindWindowA", "FindWindowW",
            "GetWindowTextA", "GetWindowTextW",
            "EnumWindows",
        ],
        # Keylogging / spyware
        "anti_debug.hook_install": [
            "SetWindowsHookA", "SetWindowsHookW",
            "SetWindowsHookExA", "SetWindowsHookExW",
        ],
        "anti_sandbox.input_state": [
            "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
            "BlockInput",
        ],
    },
    "ws2_32.dll": {
        "network.socket_ops": [
            "socket", "connect", "send", "recv",
            "bind", "listen", "accept",
            "WSAStartup", "WSAConnect",
        ],
        "network.name_resolution": [
            "gethostbyname", "getaddrinfo", "GetAddrInfoW",
            "inet_addr", "inet_ntoa",
        ],
    },
    "winhttp.dll": {
        "network.http_client": [
            "WinHttpOpen", "WinHttpConnect",
            "WinHttpOpenRequest", "WinHttpSendRequest",
            "WinHttpReceiveResponse",
        ],
    },
    "wininet.dll": {
        "network.http_client": [
            "InternetOpenA", "InternetOpenW",
            "InternetConnectA", "InternetConnectW",
            "HttpOpenRequestA", "HttpOpenRequestW",
            "HttpSendRequestA", "HttpSendRequestW",
            "URLDownloadToFileA", "URLDownloadToFileW",
        ],
    },
    "msvcrt.dll": {
        "injection.function_resolution": [
            "system",
        ],
    },
    "shell32.dll": {
        "injection.process_hollowing": [
            "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
        ],
    },
}


# ── String-based indicator patterns ─────────────────────────────────────────
#
# Structure: { category.technique_id: [patterns] }
# Patterns are plain substrings (case-insensitive comparison).

_STRING_PATTERNS: dict[str, list[str]] = {
    "anti_vm.vm_artifacts": [
        # VMware process/service names
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "vmacthlp.exe", "vmount2.exe",
        # VirtualBox process/service names
        "vboxservice.exe", "vboxtray.exe",
        "vmsrvc.exe", "vmusrvc.exe",
        # VM driver / device paths
        "vmhgfs.sys", "vmmouse.sys", "vmrawdsk.sys",
        "vboxmouse.sys", "vboxguest.sys", "vboxsf.sys",
        # Registry string fragments
        "vmware, inc.", "vmware tools",
        "oracle virtualbox guest",
        "innotek gmbh",
        # CPUID hypervisor brand strings
        "vmwarevm", "xenvmm128", "microsoft hv",
        "kvmkvmkvm",
        # Other hypervisors
        "qemu", "bochs bios",
        "virtual machine",
    ],
    "anti_vm.vm_registry": [
        r"software\vmware, inc.",
        r"software\oracle\virtualbox",
        r"hardware\acpi\dsdt\vbox",
        r"hardware\acpi\fadt\vbox",
        r"hardware\description\system",      # BIOS string reads
        r"system\currentcontrolset\services\vmhgfs",
        r"system\currentcontrolset\services\vboxsf",
    ],
    "anti_sandbox.sandbox_artifacts": [
        # Sandbox environments
        "cuckoo", "cuckoomon",
        "sandboxie", "sbiedll.dll",
        "joesandbox", "threatanalyzer", "totalsecurity",
        # Sandbox indicator paths
        r"c:\analysis",
        r"c:\sandbox",
        r"c:\insidetm",
        r"c:\cuckoo",
        r"c:\detonation",
        # Analysis tool process names (tools commonly present only in sandboxes)
        "wireshark.exe", "procmon.exe", "procmon64.exe",
        "processhacker.exe", "tcpview.exe", "filemon.exe",
        "regmon.exe", "autoruns.exe",
        "fiddler.exe", "charles.exe",
        "apate dns",
    ],
    "anti_debug.string_indicators": [
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "ntglobalflag",
        "heap flags",
        "forceflags",
        "beingdebugged",
    ],
    "anti_debug.debugger_names": [
        "ollydbg", "x64dbg", "x32dbg",
        "windbg", "ida pro", "immunity debugger",
        "dnspy", "de4dot", "x64dbg.exe", "windbg.exe",
    ],
    "privesc.privilege_strings": [
        "SeDebugPrivilege",
        "SeTcbPrivilege",
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeLoadDriverPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
    ],
    "persistence.autorun_keys": [
        r"software\microsoft\windows\currentversion\run",
        r"software\microsoft\windows\currentversion\runonce",
        r"software\microsoft\windows\currentversion\runservices",
        r"software\microsoft\windows nt\currentversion\winlogon",
        r"system\currentcontrolset\services",
        r"software\microsoft\windows\currentversion\explorer\shellexecutehooks",
        r"software\microsoft\windows nt\currentversion\image file execution options",
    ],
    "stealth.rootkit_strings": [
        "NtfsDisable8dot3NameCreation",
        "NtfsDisableLastAccessUpdate",
        # DKOM / direct object manipulation hints
        "\\Device\\PhysicalMemory",
        "\\\\?\\PhysicalDriveRaw",
        "\\Device\\HarddiskVolume",
        "DKOM",
    ],
    "network.c2_patterns": [
        # Command execution / LOLBin abuse
        "cmd.exe /c",
        "powershell -e ",
        "powershell -encodedcommand",
        "powershell -nop",
        "/bin/sh -c",
        "wget http",
        "curl http",
        "regsvr32.exe /s /n",
        "mshta http",
        "wscript.exe",
        "certutil -urlcache",
    ],
}


# Category → severity mapping
_CATEGORY_SEVERITY: dict[str, str] = {
    "anti_debug":       "MEDIUM",
    "anti_vm":          "MEDIUM",
    "anti_sandbox":     "HIGH",
    "injection":        "HIGH",
    "privesc":          "HIGH",
    "persistence":      "HIGH",
    "credential_access": "HIGH",
    "network":          "MEDIUM",
    "packer":           "MEDIUM",
    "stealth":          "HIGH",
    "anti_forensics":   "MEDIUM",
}

# Base score contribution per category (used in composite scoring)
_CATEGORY_SCORES: dict[str, int] = {
    "anti_debug":       12,
    "anti_vm":          15,
    "anti_sandbox":     18,
    "injection":        25,
    "privesc":          20,
    "persistence":      18,
    "credential_access": 15,
    "network":          10,
    "packer":           10,
    "stealth":          20,
    "anti_forensics":   12,
}


# ── Data structures ────────────────────────────────────────────────────────

@dataclass
class EvasionIndicator:
    """A single detected evasion technique."""
    category:   str         # e.g. "injection", "anti_debug"
    technique:  str         # e.g. "injection.nt_thread"
    source:     str         # "imports" | "strings" | "metadata"
    evidence:   list[str]   # specific functions / strings / flag names that matched
    confidence: int = 70


@dataclass
class EvasionProfile:
    """Aggregate result of evasion analysis."""
    indicators:      list[EvasionIndicator] = field(default_factory=list)
    score:           int                    = 0
    score_breakdown: dict[str, int]         = field(default_factory=dict)

    @property
    def has_anti_debug(self) -> bool:
        return any(i.category == "anti_debug" for i in self.indicators)

    @property
    def has_anti_vm(self) -> bool:
        return any(i.category == "anti_vm" for i in self.indicators)

    @property
    def has_anti_sandbox(self) -> bool:
        return any(i.category == "anti_sandbox" for i in self.indicators)

    @property
    def has_injection(self) -> bool:
        return any(i.category == "injection" for i in self.indicators)

    @property
    def has_privesc(self) -> bool:
        return any(i.category == "privesc" for i in self.indicators)

    @property
    def has_persistence(self) -> bool:
        return any(i.category == "persistence" for i in self.indicators)

    @property
    def has_network_c2(self) -> bool:
        return any(i.category == "network" for i in self.indicators)


# ── Analysis functions ────────────────────────────────────────────────────

def analyze_imports(imports: list[dict]) -> list[EvasionIndicator]:
    """
    Match PE import table entries against the indicator tables.

    Args:
        imports: list of {"dll": str, "functions": [str, ...]}

    Returns:
        List of EvasionIndicator records (one per matched technique).
    """
    dll_funcs: dict[str, set[str]] = {}
    for imp in imports:
        dll = imp.get("dll", "").lower()
        fns = set(imp.get("functions", []))
        if dll:
            dll_funcs[dll] = dll_funcs.get(dll, set()) | fns

    indicators: list[EvasionIndicator] = []

    for dll, technique_map in _IMPORT_TABLE.items():
        if dll not in dll_funcs:
            continue
        present_fns = dll_funcs[dll]
        for technique_id, expected_fns in technique_map.items():
            matched = [f for f in expected_fns if f in present_fns]
            if matched:
                category = technique_id.split(".")[0]
                indicators.append(EvasionIndicator(
                    category=category,
                    technique=technique_id,
                    source="imports",
                    evidence=sorted(matched),
                    confidence=_confidence_from_evidence(matched, expected_fns),
                ))

    return indicators


def analyze_strings(strings: list[str]) -> list[EvasionIndicator]:
    """
    Scan extracted strings for known evasion string patterns.

    Args:
        strings: list of printable strings extracted from the binary

    Returns:
        List of EvasionIndicator records.
    """
    lowered = [s.lower() for s in strings]

    indicators: list[EvasionIndicator] = []

    for technique_id, patterns in _STRING_PATTERNS.items():
        matched: list[str] = []
        for pat_lower in [p.lower() for p in patterns]:
            for s in lowered:
                if pat_lower in s:
                    matched.append(pat_lower)
                    break  # count each pattern once

        if matched:
            category = technique_id.split(".")[0]
            indicators.append(EvasionIndicator(
                category=category,
                technique=technique_id,
                source="strings",
                evidence=sorted(set(matched)),
                confidence=_confidence_from_evidence(matched, patterns),
            ))

    return indicators


def analyze_metadata(pe_meta: dict) -> list[EvasionIndicator]:
    """
    Derive evasion indicators from PE optional-header metadata and section table.

    Args:
        pe_meta: dict with the following optional keys:
            dll_characteristics (int)   — DllCharacteristics WORD from optional header
            sections (list[dict])       — section records, each with:
                                            name, entropy, raw_size, characteristics
            packers (list[str])         — packer names detected from section names
            timestamp_anomaly (dict|None) — result of check_timestamp_anomaly()
            import_count (int)          — total number of imported functions
            subsystem_code (int)        — PE subsystem code (2=GUI, 3=CUI, …)

    Signals checked:
        - ASLR disabled    (DYNAMIC_BASE not set in DllCharacteristics)
        - DEP disabled     (NX_COMPAT not set in DllCharacteristics)
        - SEH disabled     (NO_SEH set in DllCharacteristics)
        - Timestamp anomaly (zero, future, or pre-1990 timestamp)
        - Packer section names
        - High-entropy sections (entropy > 7.0 with nonzero raw size)
        - RWX sections
        - Minimal import table on a user-mode executable

    Returns:
        List of EvasionIndicator records, source == "metadata".
    """
    indicators: list[EvasionIndicator] = []

    dll_chars      = pe_meta.get("dll_characteristics")
    sections       = pe_meta.get("sections", [])
    packers        = pe_meta.get("packers", [])
    ts_anomaly     = pe_meta.get("timestamp_anomaly")
    import_count   = pe_meta.get("import_count", -1)
    subsystem_code = pe_meta.get("subsystem_code", 0)

    # DllCharacteristics checks apply only to user-mode executables, not
    # native subsystem / kernel drivers (subsystem 0 or 1).
    is_usermode = subsystem_code in _USERMODE_SUBSYSTEMS

    if dll_chars is not None and is_usermode:
        if not (dll_chars & _DLLCHAR_DYNAMIC_BASE):
            indicators.append(EvasionIndicator(
                category="anti_forensics",
                technique="anti_forensics.aslr_disabled",
                source="metadata",
                evidence=["DYNAMIC_BASE not set in DllCharacteristics"],
                confidence=75,
            ))
        if not (dll_chars & _DLLCHAR_NX_COMPAT):
            indicators.append(EvasionIndicator(
                category="injection",
                technique="injection.dep_disabled",
                source="metadata",
                evidence=["NX_COMPAT not set in DllCharacteristics"],
                confidence=70,
            ))
        if dll_chars & _DLLCHAR_NO_SEH:
            indicators.append(EvasionIndicator(
                category="anti_debug",
                technique="anti_debug.seh_disabled",
                source="metadata",
                evidence=["NO_SEH set in DllCharacteristics"],
                confidence=65,
            ))

    # Timestamp anomaly → evidence of deliberate header manipulation
    if ts_anomaly:
        indicators.append(EvasionIndicator(
            category="anti_forensics",
            technique="anti_forensics.timestamp_anomaly",
            source="metadata",
            evidence=[ts_anomaly.get("type", "unknown_anomaly")],
            confidence=70,
        ))

    # Packer section names → strong packing signal
    if packers:
        indicators.append(EvasionIndicator(
            category="packer",
            technique="packer.section_names",
            source="metadata",
            evidence=sorted(packers),
            confidence=90,
        ))

    # High-entropy sections (threshold > 7.0) — packed / encrypted content
    high_ent = [
        s for s in sections
        if s.get("entropy", 0.0) >= _HIGH_ENTROPY_THRESHOLD and s.get("raw_size", 0) > 0
    ]
    if high_ent:
        ent_conf = min(60 + len(high_ent) * 10, 90)
        indicators.append(EvasionIndicator(
            category="packer",
            technique="packer.high_entropy",
            source="metadata",
            evidence=sorted(f"{s['name']}:{s['entropy']:.2f}" for s in high_ent),
            confidence=ent_conf,
        ))

    # RWX sections — readable + writable + executable
    rwx = [
        s for s in sections
        if (s.get("characteristics", 0) & _SCN_RWX_MASK) == _SCN_RWX_MASK
    ]
    if rwx:
        rwx_conf = min(75 + len(rwx) * 5, 90)
        indicators.append(EvasionIndicator(
            category="injection",
            technique="injection.rwx_section",
            source="metadata",
            evidence=sorted(s["name"] for s in rwx),
            confidence=rwx_conf,
        ))

    # Minimal import table for user-mode executables (possible shellcode loader
    # or runtime-resolved API — suspicious without a packer explanation)
    if (
        import_count >= 0
        and is_usermode
        and import_count < _MINIMAL_IMPORT_THRESHOLD
        and not packers
    ):
        indicators.append(EvasionIndicator(
            category="anti_debug",
            technique="anti_debug.minimal_imports",
            source="metadata",
            evidence=[f"import_count={import_count}"],
            confidence=60,
        ))

    return indicators


def _confidence_from_evidence(matched: list, all_expected: list) -> int:
    """
    Compute confidence 50–95 based on what fraction of expected indicators fired.
    One match → ~60; half → ~75; all → ~90.
    """
    ratio = len(matched) / max(len(all_expected), 1)
    confidence = 50 + int(45 * (1 - math.exp(-3 * ratio)))
    return min(confidence, 95)


def _compute_score_detailed(
    indicators: list[EvasionIndicator],
) -> tuple[int, dict[str, int]]:
    """
    Compute aggregate score (0–100) with per-category breakdown.

    Each category contributes its base score, with diminishing returns for
    additional techniques within the same category:
        contribution = base × (1 − 0.7^n) / (1 − 0.7)

    Returns:
        (total_score, {category: score_contribution})
    """
    if not indicators:
        return 0, {}

    by_category: dict[str, list[EvasionIndicator]] = {}
    for ind in indicators:
        by_category.setdefault(ind.category, []).append(ind)

    breakdown: dict[str, int] = {}
    total = 0.0

    for category, inds in by_category.items():
        base = _CATEGORY_SCORES.get(category, 8)
        n    = len(inds)
        # Geometric series gives diminishing returns: each extra technique
        # adds 70% of the previous contribution.
        contrib = base * (1 - 0.7 ** n) / (1 - 0.7)
        cat_score = min(int(contrib), base * 3)   # cap single-category contribution
        breakdown[category] = cat_score
        total += contrib

    return min(int(total), 100), breakdown


def compute_score(indicators: list[EvasionIndicator]) -> int:
    """
    Compute an aggregate evasion score (0–100).

    Each category contributes its base score at most once.
    Multiple techniques within a category give diminishing returns.
    """
    score, _ = _compute_score_detailed(indicators)
    return score


def build_evasion_profile(
    imports:  list[dict],
    strings:  list[str],
    metadata: dict | None = None,
) -> EvasionProfile:
    """
    Run all heuristics and produce a complete EvasionProfile.

    Args:
        imports:  PE import records from parse_import_directory()
        strings:  Extracted strings from the binary (can be empty list)
        metadata: Optional PE header / section signals dict; see analyze_metadata()
                  for the expected keys.
    """
    indicators = analyze_imports(imports) + analyze_strings(strings)
    if metadata is not None:
        indicators += analyze_metadata(metadata)
    score, breakdown = _compute_score_detailed(indicators)
    return EvasionProfile(indicators=indicators, score=score, score_breakdown=breakdown)


# ── Finding serialization ─────────────────────────────────────────────────

def evasion_profile_to_findings(
    profile: EvasionProfile,
    source:  str = "pe-analyzer",
) -> list[dict]:
    """
    Convert an EvasionProfile into partial.schema.json finding records.

    One finding is emitted per unique (category, technique) combination.
    Finding IDs are stable and content-derived.
    """
    if not profile.indicators:
        return []

    now = datetime.now(timezone.utc).isoformat()
    findings: list[dict] = []

    # Group by (category, technique) so import + string + metadata hits merge
    groups: dict[tuple[str, str], list[EvasionIndicator]] = {}
    for ind in profile.indicators:
        key = (ind.category, ind.technique)
        groups.setdefault(key, []).append(ind)

    for (category, technique), inds in sorted(groups.items()):
        all_evidence  = sorted({e for ind in inds for e in ind.evidence})
        avg_confidence = int(sum(i.confidence for i in inds) / len(inds))
        severity      = _CATEGORY_SEVERITY.get(category, "MEDIUM")

        # Stable ID derived from technique slug
        finding_id = "evasion-" + technique.replace(".", "-").replace("_", "-")

        # Evidence type: prefer "function" if any import source, else "string"
        # For metadata-sourced indicators use "header_field"
        sources = {i.source for i in inds}
        if "imports" in sources:
            ev_type = "function"
        elif "metadata" in sources:
            ev_type = "header_field"
        else:
            ev_type = "string"

        findings.append({
            "id":          finding_id,
            "title":       _technique_title(category, technique),
            "severity":    severity,
            "confidence":  avg_confidence,
            "description": _technique_description(category, technique, all_evidence),
            "evidence": [
                {"type": ev_type, "value": e}
                for e in all_evidence[:10]
            ],
            "tags": [category, "evasion"],
            "source": source,
            "references": _technique_references(technique),
            "created_at": now,
        })

    return sorted(findings, key=lambda f: f["id"])


def _technique_title(category: str, technique: str) -> str:
    _TITLES: dict[str, str] = {
        "anti_debug.debugger_presence":    "Debugger Presence Check",
        "anti_debug.timing_check":         "Anti-Debug Timing Check",
        "anti_debug.nt_query":             "NtQueryInformationProcess Debugger Check",
        "anti_debug.thread_hiding":        "Thread Hidden from Debugger",
        "anti_debug.hook_install":         "Keyboard/Mouse Hook Installation",
        "anti_debug.string_indicators":    "Anti-Debug String Indicators",
        "anti_debug.debugger_names":       "Debugger Name String Indicators",
        "anti_debug.seh_disabled":         "Structured Exception Handling Disabled",
        "anti_debug.minimal_imports":      "Minimal Import Table (Possible Shellcode/Loader)",
        "anti_vm.vm_artifacts":            "Virtual Machine Artifact Detection",
        "anti_vm.vm_registry":             "Virtual Machine Registry Check",
        "anti_sandbox.sandbox_artifacts":  "Sandbox Tool Detection",
        "anti_sandbox.window_check":       "Sandbox Window Enumeration",
        "anti_sandbox.input_state":        "User Input State Check (Sandbox Evasion)",
        "injection.memory_ops":            "Remote Process Memory Manipulation",
        "injection.thread_creation":       "Remote Thread Injection",
        "injection.process_hollowing":     "Process Hollowing",
        "injection.nt_memory":             "Native API Memory Injection",
        "injection.nt_thread":             "Native API Thread Injection",
        "injection.process_enumeration":   "Process Enumeration (Pre-injection)",
        "injection.dll_load":              "Dynamic DLL Loading",
        "injection.function_resolution":   "Dynamic Function Resolution (GetProcAddress)",
        "injection.dep_disabled":          "Data Execution Prevention Disabled",
        "injection.rwx_section":           "Read-Write-Execute Section",
        "privesc.token_manipulation":      "Access Token Manipulation",
        "privesc.privilege_lookup":        "Privilege Lookup (Privilege Escalation Prep)",
        "privesc.privilege_strings":       "Sensitive Privilege Name in Binary",
        "persistence.file_ops":            "File Copy/Move Operations",
        "persistence.registry_write":      "Registry Write (Persistence)",
        "persistence.service_install":     "Windows Service Installation",
        "persistence.autorun_keys":        "Autorun Registry Key Reference",
        "credential_access.crypto":        "Cryptographic API Usage",
        "network.socket_ops":              "Raw Socket Operations",
        "network.name_resolution":         "Network Name Resolution",
        "network.http_client":             "HTTP Client API Usage",
        "network.c2_patterns":             "Command Execution / C2 Pattern",
        "packer.decompression":            "Runtime Decompression (Packer Signature)",
        "packer.section_names":            "Packer Section Names Detected",
        "packer.high_entropy":             "High-Entropy Sections (Packed/Encrypted Content)",
        "stealth.rootkit_strings":         "Rootkit / Stealth String Indicators",
        "anti_forensics.aslr_disabled":    "ASLR Disabled in PE Header",
        "anti_forensics.timestamp_anomaly": "PE Timestamp Anomaly (Header Manipulation)",
    }
    return _TITLES.get(
        technique,
        f"{category.replace('_', ' ').title()} — {technique.split('.')[-1]}",
    )


def _technique_description(category: str, technique: str, evidence: list[str]) -> str:
    count = len(evidence)
    ev_sample = ", ".join(f"'{e}'" for e in evidence[:4])
    suffix = f" ({count} indicator{'s' if count != 1 else ''}: {ev_sample})"
    return _technique_title(category, technique) + " detected" + suffix + "."


def _technique_references(technique: str) -> list[str]:
    """Return relevant MITRE ATT&CK or other references for a technique."""
    _REFS: dict[str, list[str]] = {
        "anti_debug.debugger_presence":    ["https://attack.mitre.org/techniques/T1622/"],
        "anti_debug.timing_check":         ["https://attack.mitre.org/techniques/T1622/"],
        "anti_debug.nt_query":             ["https://attack.mitre.org/techniques/T1622/"],
        "anti_debug.thread_hiding":        ["https://attack.mitre.org/techniques/T1622/"],
        "anti_vm.vm_artifacts":            ["https://attack.mitre.org/techniques/T1497/"],
        "anti_vm.vm_registry":             ["https://attack.mitre.org/techniques/T1497/001/"],
        "anti_sandbox.sandbox_artifacts":  ["https://attack.mitre.org/techniques/T1497/"],
        "anti_sandbox.window_check":       ["https://attack.mitre.org/techniques/T1497/003/"],
        "anti_sandbox.input_state":        ["https://attack.mitre.org/techniques/T1497/002/"],
        "injection.memory_ops":            ["https://attack.mitre.org/techniques/T1055/"],
        "injection.thread_creation":       ["https://attack.mitre.org/techniques/T1055/003/"],
        "injection.process_hollowing":     ["https://attack.mitre.org/techniques/T1055/012/"],
        "injection.nt_memory":             ["https://attack.mitre.org/techniques/T1055/"],
        "injection.nt_thread":             ["https://attack.mitre.org/techniques/T1055/"],
        "injection.rwx_section":           ["https://attack.mitre.org/techniques/T1055/"],
        "injection.dep_disabled":          ["https://attack.mitre.org/techniques/T1055/"],
        "privesc.token_manipulation":      ["https://attack.mitre.org/techniques/T1134/"],
        "persistence.registry_write":      ["https://attack.mitre.org/techniques/T1547/001/"],
        "persistence.service_install":     ["https://attack.mitre.org/techniques/T1543/003/"],
        "persistence.autorun_keys":        ["https://attack.mitre.org/techniques/T1547/001/"],
        "network.socket_ops":              ["https://attack.mitre.org/techniques/T1095/"],
        "network.http_client":             ["https://attack.mitre.org/techniques/T1071/001/"],
        "network.c2_patterns":             ["https://attack.mitre.org/techniques/T1059/"],
        "packer.decompression":            ["https://attack.mitre.org/techniques/T1027/002/"],
        "packer.section_names":            ["https://attack.mitre.org/techniques/T1027/002/"],
        "packer.high_entropy":             ["https://attack.mitre.org/techniques/T1027/002/"],
        "anti_forensics.aslr_disabled":    ["https://attack.mitre.org/techniques/T1562/"],
        "anti_forensics.timestamp_anomaly": ["https://attack.mitre.org/techniques/T1070/006/"],
    }
    return _REFS.get(technique, [])
