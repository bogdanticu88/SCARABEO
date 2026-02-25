"""PE Analyzer - Static analysis of Portable Executable files."""

import hashlib
import json
import logging
import math
import os
import re
import struct
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# scarabeo/evasion.py is copied into the container at build time as evasion.py
from evasion import build_evasion_profile, evasion_profile_to_findings

logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}',
)
logger = logging.getLogger(__name__)

WORK_DIR = Path("/work")
INPUT_PATH = WORK_DIR / "input.json"
OUT_DIR = WORK_DIR / "output"
ARTIFACTS_DIR = OUT_DIR / "artifacts"
SAMPLE_PATH = WORK_DIR / "sample"

# ── PE constants ────────────────────────────────────────────────────────────

DOS_HEADER_MAGIC = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"

# Section characteristic flags
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ    = 0x40000000
SCN_MEM_WRITE   = 0x80000000

# Thunk ordinal flag: set = import by ordinal, clear = import by name
IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000

MACHINE_TYPES = {
    0x14c:  "i386",
    0x8664: "AMD64",
    0x1c0:  "ARM",
    0xaa64: "ARM64",
    0x200:  "IA64",
}

SUBSYSTEMS = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "XBOX",
    16: "Windows Boot Application",
}

# DLL → suspicious function list
SUSPICIOUS_IMPORTS: dict[str, list[str]] = {
    "kernel32.dll": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "CreateProcess", "ShellExecuteA", "ShellExecuteW", "WinExec",
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
        "URLDownloadToFileA", "URLDownloadToFileW",
    ],
    "ntdll.dll": [
        "NtCreateThread", "NtCreateThreadEx", "NtWriteVirtualMemory",
        "NtProtectVirtualMemory", "NtUnmapViewOfSection", "RtlDecompressBuffer",
    ],
    "user32.dll": [
        "SetWindowsHookA", "SetWindowsHookW", "SetWindowsHookExA",
        "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
        "SendInput", "keybd_event", "mouse_event",
    ],
    "advapi32.dll": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
        "CryptAcquireContextW", "AdjustTokenPrivileges", "OpenProcessToken",
        "LookupPrivilegeValueA", "LookupPrivilegeValueW",
    ],
    "ws2_32.dll": [
        "socket", "connect", "send", "recv", "bind", "listen", "accept",
        "WSAStartup", "gethostbyname", "inet_addr",
    ],
    "winhttp.dll": [
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    ],
    "wininet.dll": [
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpSendRequestA",
    ],
}

# Section names → packer name
PACKER_SECTION_NAMES: dict[str, str] = {
    "UPX0":    "upx",
    "UPX1":    "upx",
    "UPX!":    "upx",
    ".ASPACK": "aspack",
    ".ADATA":  "aspack",
    ".THEMIDA": "themida",
    ".VMP0":   "vmprotect",
    ".VMP1":   "vmprotect",
    ".PETITE": "petite",
    ".MPRESS1": "mpress",
    ".MPRESS2": "mpress",
}

HIGH_ENTROPY_THRESHOLD = 7.0

# Maximum number of printable strings to extract (avoids multi-MB string lists)
_MAX_EXTRACT_STRINGS = 5000
_PRINTABLE_RE = re.compile(rb'[\x20-\x7e]{4,}')


# ── Low-level helpers ────────────────────────────────────────────────────────

def compute_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


def rva_to_offset(rva: int, sections: list[dict]) -> int | None:
    """Convert a relative virtual address to a file offset using section headers."""
    for s in sections:
        va = s["virtual_address"]
        size = s["virtual_size"] if s["virtual_size"] else s["raw_size"]
        if va <= rva < va + size:
            return rva - va + s["raw_offset"]
    return None


def extract_strings_from_binary(data: bytes) -> list[str]:
    """
    Extract printable ASCII strings (min 4 chars) from raw bytes.

    Returns at most _MAX_EXTRACT_STRINGS strings in file order.
    These are fed to the evasion engine's string-pattern heuristics.
    """
    return [
        m.group().decode("ascii", errors="replace")
        for m in _PRINTABLE_RE.finditer(data)
    ][:_MAX_EXTRACT_STRINGS]


def read_cstring(data: bytes, offset: int, max_len: int = 256) -> str:
    """Read a null-terminated ASCII string from data at offset."""
    end = data.find(b"\x00", offset, offset + max_len)
    if end == -1:
        end = offset + max_len
    try:
        return data[offset:end].decode("ascii", errors="replace")
    except Exception:
        return ""


# ── PE parsing ───────────────────────────────────────────────────────────────

def parse_dos_header(data: bytes) -> dict | None:
    if len(data) < 64 or data[:2] != DOS_HEADER_MAGIC:
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    return {"e_lfanew": e_lfanew}


def parse_pe_header(data: bytes, dos_header: dict) -> dict | None:
    e_lfanew = dos_header["e_lfanew"]
    if len(data) < e_lfanew + 4 or data[e_lfanew:e_lfanew + 4] != PE_SIGNATURE:
        return None

    coff_off = e_lfanew + 4
    if len(data) < coff_off + 20:
        return None

    machine      = struct.unpack_from("<H", data, coff_off)[0]
    num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
    timestamp    = struct.unpack_from("<I", data, coff_off + 4)[0]
    opt_hdr_size = struct.unpack_from("<H", data, coff_off + 16)[0]
    characteristics = struct.unpack_from("<H", data, coff_off + 18)[0]

    opt_off = coff_off + 20
    if len(data) < opt_off + 2:
        return None

    magic = struct.unpack_from("<H", data, opt_off)[0]
    is_pe32_plus = (magic == 0x20b)

    # image_base offset differs between PE32 and PE32+
    if is_pe32_plus:
        if len(data) < opt_off + 24:
            return None
        image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        # PE32+ optional header: subsystem at +68, data dirs start at +112
        # [1] Import Directory entry is at +120 (base + 1*8)
        subsystem_off  = opt_off + 68
        import_dir_off = opt_off + 120
    else:
        if len(data) < opt_off + 24:
            return None
        image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
        # PE32 optional header: subsystem at +68, data dirs start at +96
        # [1] Import Directory entry is at +104 (base + 1*8)
        subsystem_off  = opt_off + 68
        import_dir_off = opt_off + 104

    subsystem = 0
    if len(data) >= subsystem_off + 2:
        subsystem = struct.unpack_from("<H", data, subsystem_off)[0]

    # DllCharacteristics is at opt_off+70 for both PE32 and PE32+
    dll_chars_off = opt_off + 70
    dll_characteristics = 0
    if len(data) >= dll_chars_off + 2:
        dll_characteristics = struct.unpack_from("<H", data, dll_chars_off)[0]

    import_rva = 0
    if len(data) >= import_dir_off + 4:
        import_rva = struct.unpack_from("<I", data, import_dir_off)[0]

    section_table_off = opt_off + opt_hdr_size

    return {
        "machine":             MACHINE_TYPES.get(machine, f"unknown(0x{machine:x})"),
        "machine_code":        machine,
        "num_sections":        num_sections,
        "timestamp":           timestamp,
        "timestamp_iso":       datetime.utcfromtimestamp(timestamp).isoformat() if timestamp > 0 else None,
        "characteristics":     characteristics,
        "dll_characteristics": dll_characteristics,
        "is_pe32_plus":        is_pe32_plus,
        "image_base":          image_base,
        "subsystem":           SUBSYSTEMS.get(subsystem, f"unknown({subsystem})"),
        "subsystem_code":      subsystem,
        "import_rva":          import_rva,
        "section_table_off":   section_table_off,
        "coff_off":            coff_off,
    }


def parse_sections(data: bytes, pe_header: dict) -> list[dict]:
    sections = []
    section_table_off = pe_header["section_table_off"]
    num_sections = pe_header["num_sections"]

    for i in range(num_sections):
        off = section_table_off + i * 40
        if len(data) < off + 40:
            break

        name_raw      = data[off:off + 8]
        virtual_size  = struct.unpack_from("<I", data, off + 8)[0]
        virtual_addr  = struct.unpack_from("<I", data, off + 12)[0]
        raw_size      = struct.unpack_from("<I", data, off + 16)[0]
        raw_offset    = struct.unpack_from("<I", data, off + 20)[0]
        characteristics = struct.unpack_from("<I", data, off + 36)[0]

        name = name_raw.rstrip(b"\x00").decode("ascii", errors="replace")

        entropy = 0.0
        if raw_size > 0 and raw_offset + raw_size <= len(data):
            entropy = round(compute_entropy(data[raw_offset:raw_offset + raw_size]), 4)

        sections.append({
            "name":            name,
            "virtual_size":    virtual_size,
            "virtual_address": virtual_addr,
            "raw_size":        raw_size,
            "raw_offset":      raw_offset,
            "characteristics": characteristics,
            "entropy":         entropy,
        })

    return sections


def parse_import_directory(data: bytes, pe_header: dict, sections: list[dict]) -> list[dict]:
    """
    Walk the Import Directory Table and return per-DLL import records.

    Each record: {"dll": str, "functions": [str, ...]}

    We read IMAGE_IMPORT_DESCRIPTORs (20 bytes each) from import_rva until
    we hit an all-zero entry, then for each descriptor we walk the INT
    (Import Name Table) to get function names.
    """
    import_rva = pe_header.get("import_rva", 0)
    is_pe32_plus = pe_header["is_pe32_plus"]

    if not import_rva:
        return []

    iid_off = rva_to_offset(import_rva, sections)
    if iid_off is None:
        return []

    IID_SIZE = 20
    thunk_size = 8 if is_pe32_plus else 4
    ordinal_flag = IMAGE_ORDINAL_FLAG64 if is_pe32_plus else IMAGE_ORDINAL_FLAG32
    unpack_thunk = "<Q" if is_pe32_plus else "<I"

    imports: list[dict] = []
    cursor = iid_off

    while cursor + IID_SIZE <= len(data):
        # IMAGE_IMPORT_DESCRIPTOR layout (20 bytes):
        #   +0  OriginalFirstThunk (INT RVA)
        #   +4  TimeDateStamp
        #   +8  ForwarderChain
        #  +12  Name (DLL name RVA)
        #  +16  FirstThunk (IAT RVA)
        int_rva  = struct.unpack_from("<I", data, cursor)[0]
        name_rva = struct.unpack_from("<I", data, cursor + 12)[0]

        # All-zeros entry marks end of table
        if int_rva == 0 and name_rva == 0:
            break

        cursor += IID_SIZE

        dll_off = rva_to_offset(name_rva, sections) if name_rva else None
        dll_name = read_cstring(data, dll_off).lower() if dll_off is not None else ""
        if not dll_name:
            continue

        functions: list[str] = []

        # Use INT if available, else fall back to IAT
        thunk_rva = int_rva if int_rva else struct.unpack_from("<I", data, cursor - IID_SIZE + 16)[0]
        thunk_off = rva_to_offset(thunk_rva, sections) if thunk_rva else None

        if thunk_off is not None:
            t_cursor = thunk_off
            while t_cursor + thunk_size <= len(data):
                thunk_val = struct.unpack_from(unpack_thunk, data, t_cursor)[0]
                t_cursor += thunk_size

                if thunk_val == 0:
                    break

                if thunk_val & ordinal_flag:
                    # Import by ordinal — record as "#N"
                    ordinal = thunk_val & 0xFFFF
                    functions.append(f"#{ordinal}")
                else:
                    # Import by name: thunk_val is RVA of IMAGE_IMPORT_BY_NAME
                    # Structure: WORD Hint, BYTE Name[]
                    ibn_off = rva_to_offset(int(thunk_val), sections)
                    if ibn_off is not None and ibn_off + 2 < len(data):
                        fn_name = read_cstring(data, ibn_off + 2)
                        if fn_name:
                            functions.append(fn_name)

        imports.append({"dll": dll_name, "functions": functions})

    return imports


# ── Detection logic ──────────────────────────────────────────────────────────

def detect_packer(sections: list[dict]) -> list[str]:
    """Return sorted list of packer names identified from section names."""
    found: set[str] = set()
    for s in sections:
        key = s["name"].upper()
        if key in PACKER_SECTION_NAMES:
            found.add(PACKER_SECTION_NAMES[key])
    return sorted(found)


def detect_section_anomalies(sections: list[dict]) -> list[dict]:
    """
    Identify RWX sections and sections with extreme virtual/raw size inflation.

    Returns a list of anomaly dicts: {"section": name, "type": str, "detail": str}
    """
    anomalies: list[dict] = []
    for s in sections:
        c = s["characteristics"]
        is_exec  = bool(c & SCN_MEM_EXECUTE)
        is_read  = bool(c & SCN_MEM_READ)
        is_write = bool(c & SCN_MEM_WRITE)

        if is_exec and is_read and is_write:
            anomalies.append({
                "section": s["name"],
                "type": "rwx",
                "detail": f"section '{s['name']}' is readable, writable, and executable",
            })

        # Virtual size inflation: virt >> raw suggests runtime unpacking
        virt = s["virtual_size"]
        raw  = s["raw_size"]
        if raw > 0 and virt > raw * 4:
            anomalies.append({
                "section": s["name"],
                "type": "vsize_inflation",
                "detail": f"section '{s['name']}' virtual_size ({virt}) >> raw_size ({raw})",
            })

    return anomalies


def detect_suspicious_imports(imports: list[dict]) -> list[dict]:
    """
    Return per-DLL records that contain at least one suspicious function.

    Result: [{"dll": str, "functions": [str, ...]}]  — only suspicious fns listed.
    """
    hits: list[dict] = []
    for imp in imports:
        dll = imp["dll"].lower()
        if dll in SUSPICIOUS_IMPORTS:
            susp = [f for f in imp["functions"] if f in SUSPICIOUS_IMPORTS[dll]]
            if susp:
                hits.append({"dll": dll, "functions": susp})
            elif not imp["functions"]:
                # Stub import (no functions resolved — still flag the DLL presence)
                hits.append({"dll": dll, "functions": []})
    return hits


def check_timestamp_anomaly(pe_header: dict) -> dict | None:
    ts = pe_header.get("timestamp", 0)
    if ts == 0:
        return {"type": "zero_timestamp", "description": "PE timestamp is zero (stripped or manually cleared)"}
    try:
        ts_date = datetime.utcfromtimestamp(ts)
        if ts_date > datetime.utcnow():
            return {"type": "future_timestamp", "description": f"PE timestamp is in the future: {ts_date.isoformat()}"}
    except (OSError, OverflowError):
        pass
    if ts < 631152000:  # 1990-01-01
        return {"type": "old_timestamp", "description": "PE timestamp predates 1990"}
    return None


# ── Finding generation ────────────────────────────────────────────────────────

def generate_findings(
    pe_header: dict,
    sections: list[dict],
    imports: list[dict],
    packers: list[str],
    timestamp_anomaly: dict | None,
    section_anomalies: list[dict],
    suspicious_imports: list[dict],
) -> list[dict]:
    """
    Generate stable, deterministic finding records.

    Finding IDs are derived from content (packer name, section name, dll name,
    anomaly type) so that re-running on the same file produces identical IDs.
    """
    findings: list[dict] = []
    now = datetime.now(timezone.utc).isoformat()

    # 1. Packer detection (one finding per detected packer)
    for packer in packers:
        indicator_names = [
            s["name"] for s in sections
            if s["name"].upper() in PACKER_SECTION_NAMES
            and PACKER_SECTION_NAMES[s["name"].upper()] == packer
        ]
        findings.append({
            "id": f"pe-packer-{packer}",
            "title": f"Packer Detected: {packer.upper()}",
            "severity": "MEDIUM",
            "confidence": 85,
            "description": f"PE section names indicate the file was packed with {packer.upper()}.",
            "evidence": [{"type": "section_name", "value": n} for n in sorted(indicator_names)],
            "tags": ["packer", "evasion", "entropy"],
            "source": "pe-analyzer",
            "references": [],
            "created_at": now,
        })

    # 2. High-entropy sections (one finding that lists all flagged sections)
    high_ent = [s for s in sections if s["entropy"] >= HIGH_ENTROPY_THRESHOLD]
    if high_ent:
        findings.append({
            "id": "pe-entropy-sections",
            "title": "High-Entropy PE Sections",
            "severity": "MEDIUM",
            "confidence": 70,
            "description": (
                f"Found {len(high_ent)} section(s) with entropy >= {HIGH_ENTROPY_THRESHOLD}, "
                "indicating possible encryption or compression."
            ),
            "evidence": [
                {"type": "section_entropy", "value": f"{s['name']}:entropy={s['entropy']}"}
                for s in sorted(high_ent, key=lambda x: x["name"])
            ],
            "tags": ["entropy", "packing"],
            "source": "pe-analyzer",
            "references": [],
            "created_at": now,
        })

    # 3. Suspicious imports — one finding per DLL
    for hit in suspicious_imports:
        dll_stem = hit["dll"].rstrip(".dll").replace(".", "_")
        findings.append({
            "id": f"pe-imports-suspicious-{dll_stem}",
            "title": f"Suspicious Imports from {hit['dll']}",
            "severity": "MEDIUM",
            "confidence": 65,
            "description": (
                f"PE imports potentially dangerous functions from {hit['dll']}."
            ),
            "evidence": [{"type": "import", "value": fn} for fn in sorted(hit["functions"])],
            "tags": ["imports", "suspicious"],
            "source": "pe-analyzer",
            "references": [],
            "created_at": now,
        })

    # 4. Section anomalies
    for anom in section_anomalies:
        sname = anom["section"].lstrip(".").lower() or "unnamed"
        findings.append({
            "id": f"pe-section-{anom['type']}-{sname}",
            "title": (
                f"RWX Section: {anom['section']}"
                if anom["type"] == "rwx"
                else f"Virtual Size Inflation: {anom['section']}"
            ),
            "severity": "HIGH" if anom["type"] == "rwx" else "MEDIUM",
            "confidence": 80,
            "description": anom["detail"],
            "evidence": [{"type": "section_characteristic", "value": anom["detail"]}],
            "tags": ["section", "anomaly", "evasion"],
            "source": "pe-analyzer",
            "references": [],
            "created_at": now,
        })

    # 5. Timestamp anomaly
    if timestamp_anomaly:
        findings.append({
            "id": f"pe-timestamp-{timestamp_anomaly['type']}",
            "title": f"PE Timestamp Anomaly: {timestamp_anomaly['type']}",
            "severity": "LOW",
            "confidence": 80,
            "description": timestamp_anomaly["description"],
            "evidence": [{"type": "timestamp", "value": str(pe_header.get("timestamp", 0))}],
            "tags": ["timestamp", "anomaly"],
            "source": "pe-analyzer",
            "references": [],
            "created_at": now,
        })

    # 6. GUI subsystem with no .rsrc
    if pe_header.get("subsystem_code") == 2:
        has_rsrc = any(s["name"] == ".rsrc" for s in sections)
        if not has_rsrc:
            findings.append({
                "id": "pe-gui-no-resources",
                "title": "GUI Application Missing Resources Section",
                "severity": "LOW",
                "confidence": 40,
                "description": "PE declares Windows GUI subsystem but has no .rsrc section, which is atypical.",
                "evidence": [{"type": "subsystem", "value": "Windows GUI"}],
                "tags": ["anomaly", "gui"],
                "source": "pe-analyzer",
                "references": [],
                "created_at": now,
            })

    # Sort deterministically by id
    return sorted(findings, key=lambda f: f["id"])


# ── Public analysis entry point ───────────────────────────────────────────────

def analyze_pe_bytes(data: bytes, sha256: str) -> dict:
    """
    Analyze raw PE bytes and return a partial.schema.json-conforming dict.

    Separating this from I/O makes the logic directly testable without
    touching the filesystem or Docker paths.
    """
    dos_header = parse_dos_header(data)
    if not dos_header:
        raise ValueError("Not a valid PE file (missing or invalid DOS header)")

    pe_header = parse_pe_header(data, dos_header)
    if not pe_header:
        raise ValueError("Not a valid PE file (missing or invalid PE signature)")

    sections          = parse_sections(data, pe_header)
    imports           = parse_import_directory(data, pe_header, sections)
    packers           = detect_packer(sections)
    section_anomalies = detect_section_anomalies(sections)
    suspicious_imp    = detect_suspicious_imports(imports)
    ts_anomaly        = check_timestamp_anomaly(pe_header)

    # Structural findings (PE-specific)
    pe_findings = generate_findings(
        pe_header, sections, imports, packers,
        ts_anomaly, section_anomalies, suspicious_imp,
    )

    # Extract printable strings for evasion string-pattern analysis
    binary_strings = extract_strings_from_binary(data)

    # Metadata dict for PE-header evasion signals
    total_import_count = sum(len(imp.get("functions", [])) for imp in imports)
    pe_meta = {
        "dll_characteristics": pe_header.get("dll_characteristics", 0),
        "sections":            sections,
        "packers":             packers,
        "timestamp_anomaly":   ts_anomaly,
        "import_count":        total_import_count,
        "subsystem_code":      pe_header.get("subsystem_code", 0),
    }

    # Full evasion analysis: imports + strings + PE header metadata
    evasion_profile  = build_evasion_profile(
        imports=imports, strings=binary_strings, metadata=pe_meta,
    )
    evasion_findings = evasion_profile_to_findings(evasion_profile, source="pe-analyzer")

    findings = sorted(pe_findings + evasion_findings, key=lambda f: f["id"])

    # Artifacts — sha256 derived from artifact content where feasible
    imports_txt = "".join(
        f"{imp['dll']}: {', '.join(sorted(imp['functions']))}\n"
        for imp in sorted(imports, key=lambda x: x["dll"])
    )
    imports_sha256 = hashlib.sha256(imports_txt.encode()).hexdigest()

    pe_summary = {
        "file_type":            "pe",
        "machine":              pe_header["machine"],
        "is_pe32_plus":         pe_header["is_pe32_plus"],
        "subsystem":            pe_header["subsystem"],
        "subsystem_code":       pe_header["subsystem_code"],
        "dll_characteristics":  pe_header["dll_characteristics"],
        "timestamp":            pe_header["timestamp"],
        "timestamp_iso":        pe_header["timestamp_iso"],
        "image_base":           hex(pe_header["image_base"]),
        "num_sections":         pe_header["num_sections"],
        "sections":             sections,
        "packers_detected":     packers,
        "timestamp_anomaly":    ts_anomaly,
        "imports":              imports,
        "evasion_score":        evasion_profile.score,
        "evasion_score_breakdown": evasion_profile.score_breakdown,
        "evasion_categories":   sorted({i.category for i in evasion_profile.indicators}),
    }
    summary_sha256 = hashlib.sha256(
        json.dumps(pe_summary, sort_keys=True).encode()
    ).hexdigest()

    return {
        "schema_version":   "1.0.0",
        "analyzer_name":    "pe-analyzer",
        "analyzer_version": "0.1.0",
        "findings":         findings,
        "iocs":             [],
        "artifacts": [
            {
                "type":        "pe_summary",
                "path":        "artifacts/pe_summary.json",
                "sha256":      summary_sha256,
                "mime":        "application/json",
                "size_bytes":  len(json.dumps(pe_summary).encode()),
                "produced_by": "pe-analyzer",
            },
            {
                "type":        "imports",
                "path":        "artifacts/imports.txt",
                "sha256":      imports_sha256,
                "mime":        "text/plain",
                "size_bytes":  len(imports_txt.encode()),
                "produced_by": "pe-analyzer",
            },
        ],
        "metadata": pe_summary,
    }


# ── I/O wrappers ──────────────────────────────────────────────────────────────

def write_artifacts(pe_summary: dict, imports_txt: str) -> None:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    summary_path = ARTIFACTS_DIR / "pe_summary.json"
    with open(summary_path, "w") as f:
        json.dump(pe_summary, f, indent=2)

    imports_path = ARTIFACTS_DIR / "imports.txt"
    with open(imports_path, "w") as f:
        f.write(imports_txt)

    logger.info(f"Artifacts written to {ARTIFACTS_DIR}")


def run_analysis(input_data: dict) -> dict:
    sample_sha256 = input_data["sample_sha256"]

    if not SAMPLE_PATH.exists():
        raise FileNotFoundError(f"Sample not found: {SAMPLE_PATH}")

    with open(SAMPLE_PATH, "rb") as f:
        sample_data = f.read()

    actual = hashlib.sha256(sample_data).hexdigest()
    if actual.lower() != sample_sha256.lower():
        raise ValueError(f"Hash mismatch: expected {sample_sha256}, got {actual}")

    return analyze_pe_bytes(sample_data, sample_sha256)


def main() -> int:
    logger.info("PE Analyzer starting")

    if not INPUT_PATH.exists():
        logger.error(f"Input file not found: {INPUT_PATH}")
        return 1

    with open(INPUT_PATH) as f:
        input_data = json.load(f)

    try:
        partial = run_analysis(input_data)

        OUT_DIR.mkdir(parents=True, exist_ok=True)
        report_path = OUT_DIR / "report.json"
        with open(report_path, "w") as f:
            json.dump(partial, f, indent=2)
        logger.info(f"Report written to {report_path}")

        pe_summary = partial["metadata"]
        imports_txt = "".join(
            f"{imp['dll']}: {', '.join(sorted(imp['functions']))}\n"
            for imp in sorted(pe_summary.get("imports", []), key=lambda x: x["dll"])
        )
        write_artifacts(pe_summary, imports_txt)

        logger.info(f"PE analysis complete: {len(partial['findings'])} findings")
        return 0

    except Exception as e:
        logger.exception(f"PE analysis failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
