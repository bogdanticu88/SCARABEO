"""Static evasion heuristics for Windows PE samples.

Analyses two input sources:
    imports — list of {"dll": str, "functions": [str, ...]} records from
              the PE Import Directory Table
    strings — list of printable strings extracted from the binary

Produces an EvasionProfile containing categorized EvasionIndicators and
an aggregate score (0–100).

Public API
----------
build_evasion_profile(imports, strings) -> EvasionProfile
evasion_profile_to_findings(profile, source) -> list[dict]
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone


# ── Import-based indicator tables ─────────────────────────────────────────────
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
        # Anti-debug / sandbox evasion (window checks)
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
}

# ── String-based indicator patterns ──────────────────────────────────────────
#
# Structure: { category.technique_id: [patterns] }
# Patterns are plain substrings (case-insensitive comparison).

_STRING_PATTERNS: dict[str, list[str]] = {
    "anti_vm.vm_artifacts": [
        # Process names
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "vboxservice.exe", "vboxtray.exe",
        "vmsrvc.exe", "vmusrvc.exe",
        # Driver / device paths
        "vmhgfs.sys", "vmmouse.sys", "vmrawdsk.sys",
        "vboxmouse.sys", "vboxguest.sys", "vboxsf.sys",
        # Registry keys / strings
        "vmware, inc.", "vmware tools",
        "oracle virtualbox guest",
        "vbox__", "innotek gmbh",
        # CPUID hypervisor string fragments
        "vmwarevm", "xenvmm128", "microsoft hv",
    ],
    "anti_vm.vm_registry": [
        r"software\vmware, inc.",
        r"software\oracle\virtualbox",
        r"hardware\acpi\dsdt\vbox",
        r"hardware\acpi\fadt\vbox",
        r"hardware\description\system",   # used to read BIOS string
    ],
    "anti_sandbox.sandbox_artifacts": [
        # Sandbox process names
        "cuckoo", "cuckoomon",
        "sandboxie", "sbiedll.dll",
        # Monitoring tools often present in sandboxes
        "wireshark.exe", "procmon.exe", "procmon64.exe",
        "processhacker.exe", "tcpview.exe", "filemon.exe",
        "regmon.exe", "autoruns.exe",
        "fiddler.exe", "charles.exe",
        # Sandbox-indicator usernames / paths
        r"c:\analysis",
        r"c:\sandbox",
        r"c:\insidetm",
    ],
    "anti_debug.string_indicators": [
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "debug.exe",
        "ntglobalflag",
        "heap flags",
        "forceflags",
    ],
    "anti_debug.debugger_names": [
        "ollydbg", "x64dbg", "x32dbg",
        "windbg", "ida pro", "immunity debugger",
        "dnspy", "de4dot",
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
    ],
    "stealth.rootkit_strings": [
        "NtfsDisable8dot3NameCreation",
        "NtfsDisableLastAccessUpdate",
        # DKOM / object manipulation hints
        "\\Device\\PhysicalMemory",
        "\\\\?\\PhysicalDriveRaw",
        "\\Device\\HarddiskVolume",
    ],
    "network.c2_patterns": [
        # Common RAT / C2 string fragments
        "cmd.exe /c",
        "powershell -e ",
        "powershell -encodedcommand",
        "/bin/sh -c",
        "wget http",
        "curl http",
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
}


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class EvasionIndicator:
    """A single detected evasion technique."""
    category:  str             # e.g. "injection", "anti_debug"
    technique: str             # e.g. "injection.nt_thread"
    source:    str             # "imports" | "strings"
    evidence:  list[str]       # specific functions/strings that matched
    confidence: int = 70


@dataclass
class EvasionProfile:
    """Aggregate result of evasion analysis."""
    indicators: list[EvasionIndicator] = field(default_factory=list)
    score:      int = 0

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


# ── Analysis functions ────────────────────────────────────────────────────────

def analyze_imports(imports: list[dict]) -> list[EvasionIndicator]:
    """
    Match PE import table entries against the indicator tables.

    Args:
        imports: list of {"dll": str, "functions": [str, ...]}

    Returns:
        List of EvasionIndicator records (one per matched technique).
    """
    # Build fast lookup: dll → set(function_names)
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
    # Lowercase once for pattern matching
    lowered = [s.lower() for s in strings]

    indicators: list[EvasionIndicator] = []

    for technique_id, patterns in _STRING_PATTERNS.items():
        matched: list[str] = []
        for pat_lower in [p.lower() for p in patterns]:
            for s in lowered:
                if pat_lower in s:
                    # Record the original pattern (not the lowered input string)
                    matched.append(pat_lower)
                    break  # only count each pattern once

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


def _confidence_from_evidence(matched: list[str], all_expected: list[str]) -> int:
    """
    Compute confidence 50–95 based on how many indicators from a technique fired.
    One match → 60; half → 75; all → 90.
    """
    ratio = len(matched) / max(len(all_expected), 1)
    # Logarithmic scale: even 1 match gives reasonable confidence
    confidence = 50 + int(45 * (1 - math.exp(-3 * ratio)))
    return min(confidence, 95)


def compute_score(indicators: list[EvasionIndicator]) -> int:
    """
    Compute an aggregate evasion score (0–100).

    Each category contributes its base score at most once.
    Within a category, multiple techniques give diminishing returns.
    """
    if not indicators:
        return 0

    # Group by category
    by_category: dict[str, list[EvasionIndicator]] = {}
    for ind in indicators:
        by_category.setdefault(ind.category, []).append(ind)

    total = 0.0
    for category, inds in by_category.items():
        base = _CATEGORY_SCORES.get(category, 8)
        n = len(inds)
        # Diminishing returns: sum = base * (1 - 0.7^n) / (1 - 0.7)
        # Simplified: base * min(n, 3) with 70% decay
        contrib = base * (1 - 0.7 ** n) / (1 - 0.7)
        total += contrib

    return min(int(total), 100)


def build_evasion_profile(
    imports: list[dict],
    strings: list[str],
) -> EvasionProfile:
    """
    Run all heuristics and produce a complete EvasionProfile.

    Args:
        imports: PE import records from parse_import_directory()
        strings: Extracted strings from the binary (can be empty list)
    """
    indicators = analyze_imports(imports) + analyze_strings(strings)
    score = compute_score(indicators)
    return EvasionProfile(indicators=indicators, score=score)


# ── Finding serialization ─────────────────────────────────────────────────────

def evasion_profile_to_findings(
    profile: EvasionProfile,
    source: str = "pe-analyzer",
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

    # Group by (category, technique) so import + string hits merge
    groups: dict[tuple[str, str], list[EvasionIndicator]] = {}
    for ind in profile.indicators:
        key = (ind.category, ind.technique)
        groups.setdefault(key, []).append(ind)

    for (category, technique), inds in sorted(groups.items()):
        all_evidence = sorted({e for ind in inds for e in ind.evidence})
        avg_confidence = int(sum(i.confidence for i in inds) / len(inds))
        severity = _CATEGORY_SEVERITY.get(category, "MEDIUM")

        # Stable ID from technique slug
        finding_id = f"evasion-{technique.replace('.', '-').replace('_', '-')}"

        findings.append({
            "id":          finding_id,
            "title":       _technique_title(category, technique),
            "severity":    severity,
            "confidence":  avg_confidence,
            "description": _technique_description(category, technique, all_evidence),
            "evidence": [
                {"type": "function" if any(i.source == "imports" for i in inds) else "string",
                 "value": e}
                for e in all_evidence[:10]  # cap evidence list length
            ],
            "tags": [category, "evasion"],
            "source": source,
            "references": [],
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
        "privesc.token_manipulation":      "Access Token Manipulation",
        "privesc.privilege_lookup":        "Privilege Lookup (Privilege Escalation Prep)",
        "privesc.privilege_strings":       "Sensitive Privilege Name in Binary",
        "persistence.file_ops":            "File Copy/Move Operations",
        "persistence.registry_write":      "Registry Write (Persistence)",
        "persistence.service_install":     "Windows Service Installation",
        "persistence.autorun_keys":        "Autorun Registry Key Reference",
        "credential_access.crypto":        "Cryptographic API Usage",
        "network.socket_ops":             "Raw Socket Operations",
        "network.name_resolution":         "Network Name Resolution",
        "network.http_client":             "HTTP Client API Usage",
        "network.c2_patterns":             "Command Execution / C2 Pattern",
        "packer.decompression":            "Runtime Decompression (Packer Signature)",
        "stealth.rootkit_strings":         "Rootkit / Stealth String Indicators",
    }
    return _TITLES.get(technique, f"{category.replace('_', ' ').title()} — {technique.split('.')[-1]}")


def _technique_description(category: str, technique: str, evidence: list[str]) -> str:
    count = len(evidence)
    ev_sample = ", ".join(f"'{e}'" for e in evidence[:4])
    suffix = f" ({count} indicator{'s' if count != 1 else ''}: {ev_sample})"
    return _technique_title(category, technique) + " detected" + suffix + "."
