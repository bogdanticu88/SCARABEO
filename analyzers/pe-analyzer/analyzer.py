"""PE Analyzer - Static analysis of Portable Executable files."""

import hashlib
import json
import logging
import os
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}',
)
logger = logging.getLogger(__name__)

# S3 configuration
S3_ENDPOINT_URL = os.environ.get("S3_ENDPOINT_URL", "http://localhost:9000")
S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY", "scarabeo")
S3_SECRET_KEY = os.environ.get("S3_SECRET_KEY", "scarabeo_dev_password")
S3_BUCKET = os.environ.get("S3_BUCKET", "scarabeo-samples")

WORK_DIR = Path("/work")
INPUT_PATH = WORK_DIR / "input.json"
OUT_DIR = WORK_DIR / "output"
ARTIFACTS_DIR = OUT_DIR / "artifacts"
SAMPLE_PATH = WORK_DIR / "sample"

# PE constants
DOS_HEADER_MAGIC = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"

# Machine types
MACHINE_TYPES = {
    0x14c: "i386",
    0x14d: "MIPS",
    0x14e: "MIPS16",
    0x160: "MIPSFPU",
    0x162: "MIPSFPU16",
    0x166: "MIPSFPU128",
    0x168: "MIPSFPU128",
    0x184: "Alpha",
    0x1c0: "ARM",
    0x1d0: "ARMNT",
    0x1f0: "ARM64",
    0x200: "IA64",
    0x266: "MIPSFPU16BE",
    0x268: "MIPSFPU128BE",
    0x284: "Alpha64",
    0x366: "MIPSFPU16BE",
    0x466: "MIPSFPU128BE",
    0x8663: "AMD64",
    0x9041: "ARM64EC",
    0xc0ee: "ARMTHUMB",
}

# Subsystems
SUBSYSTEMS = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    8: "Native Windows",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "XBOX",
    16: "Windows Boot Application",
}

# Suspicious imports (simplified table)
SUSPICIOUS_IMPORTS = {
    "kernel32.dll": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "CreateProcess", "ShellExecute", "WinExec", "LoadLibrary", "GetProcAddress",
        "CreateFile", "DeleteFile", "CopyFile", "MoveFile",
        "RegSetValue", "RegCreateKey", "RegDeleteKey",
        "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
        "URLDownloadToFile", "WinHttpOpen", "WinHttpConnect",
    ],
    "ntdll.dll": [
        "NtCreateThread", "NtCreateThreadEx", "NtWriteVirtualMemory",
        "NtProtectVirtualMemory", "NtUnmapViewOfSection", "RtlDecompressBuffer",
    ],
    "user32.dll": [
        "SetWindowsHook", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
        "SendInput", "keybd_event", "mouse_event",
    ],
    "advapi32.dll": [
        "RegSetValue", "RegCreateKey", "CryptEncrypt", "CryptDecrypt",
        "CryptGenKey", "CryptAcquireContext", "AdjustTokenPrivileges",
        "OpenProcessToken", "LookupPrivilegeValue",
    ],
    "ws2_32.dll": [
        "socket", "connect", "send", "recv", "bind", "listen", "accept",
        "WSAStartup", "gethostbyname", "inet_addr",
    ],
}

# Packer indicators
PACKER_INDICATORS = {
    "upx": ["UPX0", "UPX1", "UPX!"],
    "aspack": [".aspack", ".adata"],
    "themida": [".themida"],
    "vmprotect": [".vmp0", ".vmp1"],
    "petite": [".petite"],
    "mpress": [".MPRESS1", ".MPRESS2"],
}


def parse_dos_header(data: bytes) -> dict | None:
    """Parse DOS header."""
    if len(data) < 64:
        return None

    if data[:2] != DOS_HEADER_MAGIC:
        return None

    # e_lfanew at offset 0x3C
    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    return {"e_lfanew": e_lfanew}


def parse_pe_header(data: bytes, dos_header: dict) -> dict | None:
    """Parse PE headers."""
    e_lfanew = dos_header.get("e_lfanew", 0)

    if len(data) < e_lfanew + 4:
        return None

    if data[e_lfanew:e_lfanew + 4] != PE_SIGNATURE:
        return None

    # COFF header starts right after PE signature
    coff_offset = e_lfanew + 4

    if len(data) < coff_offset + 20:
        return None

    coff_header = data[coff_offset:coff_offset + 20]

    machine = struct.unpack("<H", coff_header[0:2])[0]
    num_sections = struct.unpack("<H", coff_header[2:4])[0]
    timestamp = struct.unpack("<I", coff_header[4:8])[0]
    characteristics = struct.unpack("<H", coff_header[18:20])[0]

    # Optional header
    optional_header_offset = coff_offset + 20
    if len(data) < optional_header_offset + 2:
        return None

    magic = struct.unpack("<H", data[optional_header_offset:optional_header_offset + 2])[0]
    is_pe32_plus = magic == 0x20b

    # Parse optional header fields
    if is_pe32_plus:
        if len(data) < optional_header_offset + 24:
            return None
        image_base = struct.unpack("<Q", data[optional_header_offset + 16:optional_header_offset + 24])[0]
        subsystem_offset = optional_header_offset + 68
    else:
        if len(data) < optional_header_offset + 24:
            return None
        image_base = struct.unpack("<I", data[optional_header_offset + 16:optional_header_offset + 20])[0]
        subsystem_offset = optional_header_offset + 60

    if len(data) < subsystem_offset + 2:
        return None

    subsystem = struct.unpack("<H", data[subsystem_offset:subsystem_offset + 2])[0]

    return {
        "machine": MACHINE_TYPES.get(machine, f"unknown({hex(machine)})"),
        "machine_code": machine,
        "num_sections": num_sections,
        "timestamp": timestamp,
        "timestamp_iso": datetime.utcfromtimestamp(timestamp).isoformat() if timestamp > 0 else None,
        "characteristics": characteristics,
        "is_pe32_plus": is_pe32_plus,
        "image_base": image_base,
        "subsystem": SUBSYSTEMS.get(subsystem, f"unknown({subsystem})"),
        "subsystem_code": subsystem,
    }


def parse_sections(data: bytes, dos_header: dict, pe_header: dict) -> list[dict]:
    """Parse section headers."""
    sections = []
    e_lfanew = dos_header.get("e_lfanew", 0)
    num_sections = pe_header.get("num_sections", 0)

    # Section headers start after optional header
    # Optional header size is at offset 0x14 in COFF header
    coff_offset = e_lfanew + 4
    optional_header_size = struct.unpack("<H", data[coff_offset + 16:coff_offset + 18])[0]
    section_offset = coff_offset + 20 + optional_header_size

    for i in range(num_sections):
        offset = section_offset + (i * 40)
        if len(data) < offset + 40:
            break

        name = data[offset:offset + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        virtual_size = struct.unpack("<I", data[offset + 8:offset + 12])[0]
        virtual_address = struct.unpack("<I", data[offset + 12:offset + 16])[0]
        raw_size = struct.unpack("<I", data[offset + 16:offset + 20])[0]
        raw_offset = struct.unpack("<I", data[offset + 20:offset + 24])[0]
        characteristics = struct.unpack("<I", data[offset + 36:offset + 40])[0]

        # Compute section entropy
        if raw_size > 0 and raw_offset + raw_size <= len(data):
            section_data = data[raw_offset:raw_offset + raw_size]
            entropy = compute_entropy(section_data)
        else:
            entropy = 0.0

        sections.append({
            "name": name,
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": raw_size,
            "raw_offset": raw_offset,
            "characteristics": characteristics,
            "entropy": round(entropy, 4),
        })

    return sections


def compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy."""
    if not data:
        return 0.0

    from collections import Counter
    import math

    byte_counts = Counter(data)
    total = len(data)
    entropy = 0.0

    for count in byte_counts.values():
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)

    return entropy


def extract_imports(data: bytes, dos_header: dict, pe_header: dict) -> list[dict]:
    """Extract import information (simplified)."""
    imports = []

    # This is a simplified implementation
    # Full implementation would parse the import directory table

    # Look for DLL names in the binary
    dll_patterns = [b".dll\x00"]
    found_dlls = set()

    for pattern in dll_patterns:
        idx = 0
        while True:
            idx = data.find(pattern, idx)
            if idx == -1:
                break

            # Extract DLL name (go back to find start)
            start = idx
            while start > 0 and data[start - 1] != 0 and data[start - 1] > 32:
                start -= 1

            try:
                dll_name = data[start:idx + 4].rstrip(b"\x00").decode("ascii", errors="replace").lower()
                if dll_name and "." in dll_name:
                    found_dlls.add(dll_name)
            except Exception:
                pass

            idx += 1

    for dll in sorted(found_dlls):
        imports.append({"dll": dll, "functions": []})

    return imports


def check_timestamp_anomaly(pe_header: dict) -> dict | None:
    """Check for timestamp anomalies."""
    timestamp = pe_header.get("timestamp", 0)

    if timestamp == 0:
        return {"type": "zero_timestamp", "description": "PE timestamp is zero"}

    # Check if timestamp is in the future
    now = datetime.utcnow()
    try:
        ts_date = datetime.utcfromtimestamp(timestamp)
        if ts_date > now:
            return {"type": "future_timestamp", "description": f"PE timestamp is in the future: {ts_date}"}
    except Exception:
        pass

    # Check if timestamp is before 1990
    if timestamp < 631152000:  # 1990-01-01
        return {"type": "old_timestamp", "description": "PE timestamp is before 1990"}

    return None


def detect_packer(sections: list[dict]) -> list[str]:
    """Detect potential packers based on section names."""
    detected = []
    section_names = [s["name"].upper() for s in sections]

    for packer, indicators in PACKER_INDICATORS.items():
        for indicator in indicators:
            if indicator.upper() in section_names:
                detected.append(packer)
                break

    return sorted(detected)


def generate_findings(
    pe_header: dict,
    sections: list[dict],
    imports: list[dict],
    packers: list[str],
    timestamp_anomaly: dict | None,
) -> list[dict]:
    """Generate security findings."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    # Packer detection
    if packers:
        findings.append({
            "id": f"pe-packer-{len(findings)}",
            "title": "Potential Packer Detected",
            "severity": "MEDIUM",
            "confidence": 70,
            "description": f"PE file shows indicators of being packed: {', '.join(packers)}",
            "evidence": [{"type": "section_names", "value": str(packers)}],
            "tags": ["packer", "evasion"],
            "source": "pe-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    # High entropy sections
    high_entropy_sections = [s for s in sections if s["entropy"] > 7.0]
    if high_entropy_sections:
        findings.append({
            "id": f"pe-entropy-{len(findings)}",
            "title": "High Entropy PE Sections",
            "severity": "MEDIUM",
            "confidence": 65,
            "description": f"Found {len(high_entropy_sections)} sections with entropy > 7.0, indicating possible encryption or compression",
            "evidence": [
                {"type": "section", "value": f"{s['name']}:entropy={s['entropy']}"}
                for s in high_entropy_sections[:5]
            ],
            "tags": ["entropy", "packing"],
            "source": "pe-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    # Suspicious imports
    suspicious_found = []
    for imp in imports:
        dll = imp["dll"]
        if dll in SUSPICIOUS_IMPORTS:
            # In a full implementation, we'd check actual imported functions
            suspicious_found.append(dll)

    if suspicious_found:
        findings.append({
            "id": f"pe-imports-{len(findings)}",
            "title": "Suspicious Import DLLs",
            "severity": "LOW",
            "confidence": 50,
            "description": f"PE imports DLLs commonly used for malicious purposes: {', '.join(suspicious_found)}",
            "evidence": [{"type": "dll", "value": dll} for dll in suspicious_found],
            "tags": ["imports", "suspicious"],
            "source": "pe-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    # Timestamp anomaly
    if timestamp_anomaly:
        findings.append({
            "id": f"pe-timestamp-{len(findings)}",
            "title": f"PE Timestamp Anomaly: {timestamp_anomaly['type']}",
            "severity": "LOW",
            "confidence": 80,
            "description": timestamp_anomaly["description"],
            "evidence": [{"type": "timestamp", "value": str(pe_header.get('timestamp', 0))}],
            "tags": ["timestamp", "anomaly"],
            "source": "pe-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    # GUI subsystem without resources (potential headless malware)
    if pe_header.get("subsystem_code") == 2:  # Windows GUI
        resource_section = next((s for s in sections if s["name"] == ".rsrc"), None)
        if not resource_section:
            findings.append({
                "id": f"pe-gui-no-resources-{len(findings)}",
                "title": "GUI Application Without Resources Section",
                "severity": "LOW",
                "confidence": 40,
                "description": "PE is a GUI application but lacks a resources section, which is unusual",
                "evidence": [{"type": "subsystem", "value": "Windows GUI"}],
                "tags": ["anomaly", "gui"],
                "source": "pe-analyzer",
                "references": [],
                "affected_objects": [],
                "created_at": now,
            })

    return findings


def run_analysis(input_data: dict) -> dict:
    """Run PE analysis."""
    logger.info("Starting PE analysis")

    sample_sha256 = input_data["sample_sha256"]

    # Read local sample
    if not SAMPLE_PATH.exists():
        raise FileNotFoundError(f"Sample file not found: {SAMPLE_PATH}")

    logger.info(f"Reading sample from {SAMPLE_PATH}")
    with open(SAMPLE_PATH, "rb") as f:
        sample_data = f.read()

    # Verify hash
    actual_hash = hashlib.sha256(sample_data).hexdigest()
    if actual_hash.lower() != sample_sha256.lower():
        raise ValueError(f"Hash mismatch: expected {sample_sha256}, got {actual_hash}")

    # Parse PE
    dos_header = parse_dos_header(sample_data)
    if not dos_header:
        raise ValueError("Not a valid PE file (missing DOS header)")

    pe_header = parse_pe_header(sample_data, dos_header)
    if not pe_header:
        raise ValueError("Not a valid PE file (missing PE header)")

    sections = parse_sections(sample_data, dos_header, pe_header)
    imports = extract_imports(sample_data, dos_header, pe_header)
    packers = detect_packer(sections)
    timestamp_anomaly = check_timestamp_anomaly(pe_header)

    # Generate findings
    findings = generate_findings(pe_header, sections, imports, packers, timestamp_anomaly)

    # Create PE summary
    pe_summary = {
        "file_type": "PE",
        "machine": pe_header["machine"],
        "subsystem": pe_header["subsystem"],
        "timestamp": pe_header["timestamp"],
        "timestamp_iso": pe_header["timestamp_iso"],
        "is_pe32_plus": pe_header["is_pe32_plus"],
        "image_base": hex(pe_header["image_base"]),
        "num_sections": pe_header["num_sections"],
        "sections": sections,
        "packers_detected": packers,
        "timestamp_anomaly": timestamp_anomaly,
        "imports": imports,
    }

    # Create partial output
    now = datetime.now(timezone.utc).isoformat()
    partial = {
        "schema_version": "1.0.0",
        "analyzer_name": "pe-analyzer",
        "analyzer_version": "0.1.0",
        "findings": sorted(findings, key=lambda f: f["id"]),
        "iocs": [],  # PE analysis doesn't typically extract IOCs
        "artifacts": [
            {
                "type": "pe_summary",
                "path": "artifacts/pe_summary.json",
                "produced_by": "pe-analyzer",
            }
        ],
        "metadata": pe_summary,
    }

    logger.info(f"PE analysis complete: {len(findings)} findings, {len(sections)} sections")
    return partial


def write_artifacts(pe_summary: dict) -> None:
    """Write artifacts to output directory."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    # Write PE summary
    summary_path = ARTIFACTS_DIR / "pe_summary.json"
    with open(summary_path, "w") as f:
        json.dump(pe_summary, f, indent=2)

    # Write imports list
    imports_path = ARTIFACTS_DIR / "imports.txt"
    with open(imports_path, "w") as f:
        for imp in sorted(pe_summary.get("imports", []), key=lambda x: x["dll"]):
            f.write(f"{imp['dll']}\n")

    logger.info(f"Wrote artifacts to {ARTIFACTS_DIR}")


def main() -> int:
    """Main entry point."""
    logger.info("PE Analyzer starting")

    if not INPUT_PATH.exists():
        logger.error(f"Input file not found: {INPUT_PATH}")
        return 1

    with open(INPUT_PATH, "r") as f:
        input_data = json.load(f)

    try:
        partial = run_analysis(input_data)

        OUT_DIR.mkdir(parents=True, exist_ok=True)

        # Write report
        report_path = OUT_DIR / "report.json"
        with open(report_path, "w") as f:
            json.dump(partial, f, indent=2)

        logger.info(f"Report written to {report_path}")

        # Write artifacts
        write_artifacts(partial["metadata"])

        logger.info("PE analysis completed successfully")
        return 0

    except Exception as e:
        logger.exception(f"PE analysis failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
