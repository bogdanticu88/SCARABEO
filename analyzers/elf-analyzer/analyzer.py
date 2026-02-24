"""ELF Analyzer - Static analysis of ELF files."""

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

WORK_DIR = Path("/work")
INPUT_PATH = WORK_DIR / "input.json"
OUT_DIR = WORK_DIR / "output"
ARTIFACTS_DIR = OUT_DIR / "artifacts"
SAMPLE_PATH = WORK_DIR / "sample"

# ELF constants
ELF_MAGIC = b"\x7fELF"

# ELF class
ELF_CLASS = {1: "32-bit", 2: "64-bit"}

# ELF data encoding
ELF_DATA = {1: "Little Endian", 2: "Big Endian"}

# ELF type
ELF_TYPE = {
    0: "NONE",
    1: "REL",
    2: "EXEC",
    3: "DYN",
    4: "CORE",
}

# ELF machine
ELF_MACHINE = {
    0: "None",
    3: "i386",
    8: "MIPS",
    20: "PowerPC",
    40: "ARM",
    50: "IA-64",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}

# Suspicious functions (simplified)
SUSPICIOUS_FUNCTIONS = [
    "ptrace", "mprotect", "mmap", "munmap",
    "execve", "fork", "vfork", "clone",
    "socket", "connect", "bind", "listen", "accept",
    "send", "recv", "sendto", "recvfrom",
    "open", "read", "write", "close",
    "unlink", "rename", "mkdir", "rmdir",
    "chmod", "chown", "symlink", "readlink",
    "setuid", "setgid", "setreuid", "setregid",
    "getuid", "geteuid", "getgid", "getegid",
    "dlopen", "dlsym", "dlclose",
]


def parse_elf_header(data: bytes) -> dict | None:
    """Parse ELF header."""
    if len(data) < 52:
        return None

    if data[:4] != ELF_MAGIC:
        return None

    elf_class = data[4]
    elf_data = data[5]

    is_64bit = elf_class == 2
    is_little_endian = elf_data == 1

    endian = "<" if is_little_endian else ">"

    if is_64bit:
        if len(data) < 64:
            return None

        e_type = struct.unpack(f"{endian}H", data[16:18])[0]
        e_machine = struct.unpack(f"{endian}H", data[18:20])[0]
        e_entry = struct.unpack(f"{endian}Q", data[24:32])[0]
        e_phoff = struct.unpack(f"{endian}Q", data[32:40])[0]
        e_shoff = struct.unpack(f"{endian}Q", data[40:48])[0]
        e_phentsize = struct.unpack(f"{endian}H", data[54:56])[0]
        e_phnum = struct.unpack(f"{endian}H", data[56:58])[0]
        e_shentsize = struct.unpack(f"{endian}H", data[58:60])[0]
        e_shnum = struct.unpack(f"{endian}H", data[60:62])[0]
    else:
        e_type = struct.unpack(f"{endian}H", data[16:18])[0]
        e_machine = struct.unpack(f"{endian}H", data[18:20])[0]
        e_entry = struct.unpack(f"{endian}I", data[24:28])[0]
        e_phoff = struct.unpack(f"{endian}I", data[28:32])[0]
        e_shoff = struct.unpack(f"{endian}I", data[32:36])[0]
        e_phentsize = struct.unpack(f"{endian}H", data[42:44])[0]
        e_phnum = struct.unpack(f"{endian}H", data[44:46])[0]
        e_shentsize = struct.unpack(f"{endian}H", data[46:48])[0]
        e_shnum = struct.unpack(f"{endian}H", data[48:50])[0]

    return {
        "class": ELF_CLASS.get(elf_class, f"unknown({elf_class})"),
        "data": ELF_DATA.get(elf_data, f"unknown({elf_data})"),
        "type": ELF_TYPE.get(e_type, f"unknown({e_type})"),
        "machine": ELF_MACHINE.get(e_machine, f"unknown({e_machine})"),
        "entry": hex(e_entry),
        "phoff": e_phoff,
        "shoff": e_shoff,
        "phentsize": e_phentsize,
        "phnum": e_phnum,
        "shentsize": e_shentsize,
        "shnum": e_shnum,
    }


def parse_sections(data: bytes, elf_header: dict) -> list[dict]:
    """Parse section headers."""
    sections = []

    is_64bit = elf_header["class"] == "64-bit"
    is_little_endian = elf_header["data"] == "Little Endian"
    endian = "<" if is_little_endian else ">"

    shoff = elf_header["shoff"]
    shnum = elf_header["shnum"]
    shentsize = elf_header["shentsize"]

    for i in range(shnum):
        offset = shoff + (i * shentsize)

        if is_64bit:
            if len(data) < offset + 64:
                break

            sh_name = struct.unpack(f"{endian}I", data[offset:offset + 4])[0]
            sh_type = struct.unpack(f"{endian}I", data[offset + 4:offset + 8])[0]
            sh_flags = struct.unpack(f"{endian}Q", data[offset + 8:offset + 16])[0]
            sh_size = struct.unpack(f"{endian}Q", data[offset + 32:offset + 40])[0]
            sh_offset = struct.unpack(f"{endian}Q", data[offset + 24:offset + 32])[0]
        else:
            if len(data) < offset + 40:
                break

            sh_name = struct.unpack(f"{endian}I", data[offset:offset + 4])[0]
            sh_type = struct.unpack(f"{endian}I", data[offset + 4:offset + 8])[0]
            sh_flags = struct.unpack(f"{endian}I", data[offset + 8:offset + 12])[0]
            sh_size = struct.unpack(f"{endian}I", data[offset + 16:offset + 20])[0]
            sh_offset = struct.unpack(f"{endian}I", data[offset + 16:offset + 20])[0]

        # Get section name (simplified - would need string table for full names)
        section_names = {
            0: "NULL", 1: ".text", 2: ".data", 3: ".bss",
            4: ".rodata", 5: ".dynamic", 6: ".dynsym", 7: ".dynstr",
            8: ".rel.dyn", 9: ".rel.plt", 10: ".plt", 11: ".got",
            12: ".hash", 13: ".interp", 14: ".gnu.hash",
        }

        sections.append({
            "index": i,
            "name_offset": sh_name,
            "name": section_names.get(sh_name, f"sec_{i}"),
            "type": sh_type,
            "flags": sh_flags,
            "size": sh_size,
            "offset": sh_offset,
        })

    return sections


def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract strings from binary."""
    import re
    strings = []

    # ASCII strings
    ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    for match in re.finditer(ascii_pattern, data):
        try:
            string = match.group().decode('ascii', errors='strict')
            strings.append(string)
        except UnicodeDecodeError:
            pass

    return strings[:10000]  # Limit


def find_suspicious_functions(strings: list[str]) -> list[str]:
    """Find suspicious function names in strings."""
    found = []
    for s in strings:
        for func in SUSPICIOUS_FUNCTIONS:
            if func in s and func not in found:
                found.append(func)
    return sorted(found)


def check_rpath_runpath(data: bytes, strings: list[str]) -> dict | None:
    """Check for RPATH/RUNPATH."""
    rpath = None
    runpath = None

    for s in strings:
        if s.startswith("RPATH=") or s == "RPATH":
            rpath = s
        if s.startswith("RUNPATH=") or s == "RUNPATH":
            runpath = s

    if rpath or runpath:
        return {
            "rpath_present": rpath is not None,
            "runpath_present": runpath is not None,
            "rpath": rpath,
            "runpath": runpath,
        }
    return None


def generate_findings(
    elf_header: dict,
    sections: list[dict],
    suspicious_functions: list[str],
    rpath_info: dict | None,
) -> list[dict]:
    """Generate security findings."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    # Suspicious functions
    if suspicious_functions:
        findings.append({
            "id": f"elf-functions-{len(findings)}",
            "title": "Suspicious Function References",
            "severity": "MEDIUM",
            "confidence": 60,
            "description": f"Found references to {len(suspicious_functions)} potentially suspicious functions",
            "evidence": [{"type": "function", "value": f} for f in suspicious_functions[:10]],
            "tags": ["functions", "suspicious"],
            "source": "elf-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    # RPATH/RUNPATH
    if rpath_info:
        findings.append({
            "id": f"elf-rpath-{len(findings)}",
            "title": "RPATH/RUNPATH Present",
            "severity": "LOW",
            "confidence": 70,
            "description": "ELF binary has RPATH or RUNPATH set, which could be used for library hijacking",
            "evidence": [
                {"type": "rpath", "value": str(rpath_info.get("rpath"))},
                {"type": "runpath", "value": str(rpath_info.get("runpath"))},
            ],
            "tags": ["rpath", "library-hijacking"],
            "source": "elf-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    # PIE check
    if elf_header["type"] == "EXEC":
        findings.append({
            "id": f"elf-no-pie-{len(findings)}",
            "title": "Binary Not Position Independent",
            "severity": "LOW",
            "confidence": 80,
            "description": "ELF binary is not position-independent (not PIE), making ASLR less effective",
            "evidence": [{"type": "type", "value": elf_header["type"]}],
            "tags": ["pie", "aslr"],
            "source": "elf-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    return findings


def run_analysis(input_data: dict) -> dict:
    """Run ELF analysis."""
    logger.info("Starting ELF analysis")

    sample_sha256 = input_data["sample_sha256"]

    if not SAMPLE_PATH.exists():
        raise FileNotFoundError(f"Sample file not found: {SAMPLE_PATH}")

    with open(SAMPLE_PATH, "rb") as f:
        sample_data = f.read()

    actual_hash = hashlib.sha256(sample_data).hexdigest()
    if actual_hash.lower() != sample_sha256.lower():
        raise ValueError(f"Hash mismatch: expected {sample_sha256}, got {actual_hash}")

    elf_header = parse_elf_header(sample_data)
    if not elf_header:
        raise ValueError("Not a valid ELF file")

    sections = parse_sections(sample_data, elf_header)
    strings = extract_strings(sample_data)
    suspicious_functions = find_suspicious_functions(strings)
    rpath_info = check_rpath_runpath(sample_data, strings)

    findings = generate_findings(elf_header, sections, suspicious_functions, rpath_info)

    elf_summary = {
        "file_type": "ELF",
        "class": elf_header["class"],
        "data": elf_header["data"],
        "type": elf_header["type"],
        "machine": elf_header["machine"],
        "entry": elf_header["entry"],
        "num_sections": elf_header["shnum"],
        "sections": sections,
        "suspicious_functions": suspicious_functions,
        "rpath_info": rpath_info,
    }

    now = datetime.now(timezone.utc).isoformat()
    partial = {
        "schema_version": "1.0.0",
        "analyzer_name": "elf-analyzer",
        "analyzer_version": "0.1.0",
        "findings": sorted(findings, key=lambda f: f["id"]),
        "iocs": [],
        "artifacts": [
            {
                "type": "elf_summary",
                "path": "artifacts/elf_summary.json",
                "produced_by": "elf-analyzer",
            },
            {
                "type": "dyn_symbols",
                "path": "artifacts/dyn_symbols.txt",
                "produced_by": "elf-analyzer",
            },
        ],
        "metadata": elf_summary,
    }

    logger.info(f"ELF analysis complete: {len(findings)} findings")
    return partial


def write_artifacts(elf_summary: dict) -> None:
    """Write artifacts."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    summary_path = ARTIFACTS_DIR / "elf_summary.json"
    with open(summary_path, "w") as f:
        json.dump(elf_summary, f, indent=2)

    symbols_path = ARTIFACTS_DIR / "dyn_symbols.txt"
    with open(symbols_path, "w") as f:
        for func in sorted(elf_summary.get("suspicious_functions", [])):
            f.write(f"{func}\n")

    logger.info(f"Wrote artifacts to {ARTIFACTS_DIR}")


def main() -> int:
    """Main entry point."""
    logger.info("ELF Analyzer starting")

    if not INPUT_PATH.exists():
        logger.error(f"Input file not found: {INPUT_PATH}")
        return 1

    with open(INPUT_PATH, "r") as f:
        input_data = json.load(f)

    try:
        report = run_analysis(input_data)

        OUT_DIR.mkdir(parents=True, exist_ok=True)

        report_path = OUT_DIR / "report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Report written to {report_path}")
        write_artifacts(report["metadata"])

        logger.info("ELF analysis completed successfully")
        return 0

    except Exception as e:
        logger.exception(f"ELF analysis failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
