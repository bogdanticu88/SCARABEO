"""Triage Universal Analyzer - Static analysis container."""

import hashlib
import json
import logging
import math
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# scarabeo/ioc.py is copied into the container at build time as ioc.py
from ioc import (
    deduplicate_ioc_records,
    extract_iocs,
    make_ioc_records,
    sort_ioc_records,
)

# scarabeo/evasion.py is copied into the container at build time as evasion.py
from evasion import build_evasion_profile, evasion_profile_to_findings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}',
)
logger = logging.getLogger(__name__)

# Configuration from environment
CHUNK_SIZE = int(os.environ.get("ANALYZER_CHUNK_SIZE", "4096"))
MAX_STRINGS = int(os.environ.get("ANALYZER_MAX_STRINGS", "10000"))
HIGH_ENTROPY_THRESHOLD = float(os.environ.get("ANALYZER_HIGH_ENTROPY_THRESHOLD", "7.5"))

# S3 configuration
S3_ENDPOINT_URL = os.environ.get("S3_ENDPOINT_URL", "http://localhost:9000")
S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY", "scarabeo")
S3_SECRET_KEY = os.environ.get("S3_SECRET_KEY", "scarabeo_dev_password")
S3_BUCKET = os.environ.get("S3_BUCKET", "scarabeo-samples")

# Work directories
WORK_DIR = Path("/work")
INPUT_PATH = WORK_DIR / "input.json"
OUT_DIR = WORK_DIR / "output"
ARTIFACTS_DIR = OUT_DIR / "artifacts"
SAMPLE_PATH = WORK_DIR / "sample"


def compute_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of byte data.

    Args:
        data: Byte data to analyze

    Returns:
        Entropy value (0-8 for bytes)
    """
    if not data:
        return 0.0

    byte_counts = Counter(data)
    total = len(data)

    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)

    return entropy


def compute_chunk_entropies(data: bytes, chunk_size: int = CHUNK_SIZE) -> list[dict]:
    """
    Compute entropy for each chunk of data.

    Args:
        data: Byte data
        chunk_size: Size of each chunk

    Returns:
        List of chunk entropy records
    """
    entropies = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        entropy = compute_entropy(chunk)
        entropies.append({
            "offset": i,
            "size": len(chunk),
            "entropy": round(entropy, 4),
        })
    return entropies


def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """
    Extract ASCII and UTF-16LE strings from binary data.

    Args:
        data: Byte data
        min_length: Minimum string length

    Returns:
        List of extracted strings (deterministic order)
    """
    strings = []

    # ASCII strings (printable characters)
    ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    for match in re.finditer(ascii_pattern, data):
        try:
            string = match.group().decode('ascii', errors='strict')
            strings.append(("ascii", match.start(), string))
        except UnicodeDecodeError:
            pass

    # UTF-16LE strings
    utf16_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
    for match in re.finditer(utf16_pattern, data):
        try:
            string = match.group().decode('utf-16le', errors='strict')
            strings.append(("utf16le", match.start(), string))
        except UnicodeDecodeError:
            pass

    # Sort by offset for deterministic order
    strings.sort(key=lambda x: x[1])

    # Limit and return just the string values
    return [s[2] for s in strings[:MAX_STRINGS]]


# extract_iocs, normalize_ioc, and generate_ioc_records are provided by the
# imported scarabeo ioc module.  See the `ioc` import at the top of this file.


# Magic-byte signatures for file type detection (checked in order)
_FILE_MAGIC: list[tuple[bytes, int, str]] = [
    # (magic, offset, file_type)
    (b"MZ",                    0, "pe"),
    (b"\x7fELF",               0, "elf"),
    (b"PK\x03\x04",            0, "archive"),   # ZIP-based
    (b"PK\x05\x06",            0, "archive"),   # empty ZIP
    (b"Rar!\x1a\x07\x00",      0, "archive"),   # RAR4
    (b"Rar!\x1a\x07\x01\x00",  0, "archive"),   # RAR5
    (b"\x1f\x8b",              0, "archive"),   # gzip
    (b"BZh",                   0, "archive"),   # bzip2
    (b"\xfd7zXZ\x00",          0, "archive"),   # xz
    (b"7z\xbc\xaf\x27\x1c",    0, "archive"),   # 7-zip
    (b"\xd0\xcf\x11\xe0",      0, "document"),  # OLE2 (doc/xls/ppt)
    (b"%PDF-",                  0, "document"),
    (b"#!/",                    0, "script"),
    (b"#!",                     0, "script"),
]

_SCRIPT_EXTENSIONS = frozenset([
    ".ps1", ".psm1", ".psd1",
    ".vbs", ".vbe", ".js", ".jse",
    ".sh", ".bash", ".zsh",
    ".py", ".rb", ".pl",
    ".bat", ".cmd",
])


def detect_file_type(data: bytes, filename: str | None = None) -> str:
    """
    Identify file type from magic bytes, with optional filename hint.

    Returns one of: pe, elf, archive, document, script, unknown.
    """
    for magic, offset, file_type in _FILE_MAGIC:
        end = offset + len(magic)
        if len(data) >= end and data[offset:end] == magic:
            return file_type

    if filename:
        ext = Path(filename).suffix.lower()
        if ext in _SCRIPT_EXTENSIONS:
            return "script"
        if ext in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf"}:
            return "document"
        if ext in {".zip", ".rar", ".7z", ".gz", ".bz2", ".tar", ".xz"}:
            return "archive"

    return "unknown"


def verify_sha256(data: bytes, expected: str) -> bool:
    """Verify SHA256 hash of data."""
    actual = hashlib.sha256(data).hexdigest()
    return actual.lower() == expected.lower()


def generate_findings(
    data: bytes,
    iocs: dict,
    entropies: list[dict],
) -> list[dict]:
    """
    Generate security findings.

    iocs is the dict returned by scarabeo.ioc.extract_iocs() with keys:
    url, domain, ip, email, filepath, registry.
    """
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    # High entropy finding
    high_entropy_chunks = [e for e in entropies if e["entropy"] > HIGH_ENTROPY_THRESHOLD]
    if high_entropy_chunks:
        findings.append({
            "id": "triage-entropy-high",
            "title": "High Entropy Content Detected",
            "severity": "MEDIUM",
            "confidence": 75,
            "description": (
                f"Found {len(high_entropy_chunks)} chunks with entropy above "
                f"{HIGH_ENTROPY_THRESHOLD}, indicating possible encryption or packing"
            ),
            "evidence": [
                {"type": "entropy", "value": f"offset={e['offset']},entropy={e['entropy']}"}
                for e in high_entropy_chunks[:5]
            ],
            "tags": ["encryption", "packing", "entropy"],
            "source": "triage-universal",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    # Network indicators finding
    urls    = iocs.get("url", [])
    domains = iocs.get("domain", [])
    if urls or domains:
        evidence = (
            [{"type": "url",    "value": u} for u in urls[:5]]
            + [{"type": "domain", "value": d} for d in domains[:5]]
        )
        findings.append({
            "id": "triage-network-indicators",
            "title": "Network Indicators Detected",
            "severity": "HIGH",
            "confidence": 80,
            "description": (
                f"Found {len(urls)} URL(s) and {len(domains)} domain(s) embedded in sample"
            ),
            "evidence": evidence,
            "tags": ["network", "ioc", "c2"],
            "source": "triage-universal",
            "references": ["https://attack.mitre.org/techniques/T1071/"],
            "affected_objects": [],
            "created_at": now,
        })

    # Email indicators finding
    emails = iocs.get("email", [])
    if emails:
        findings.append({
            "id": "triage-email-indicators",
            "title": "Email Addresses Detected",
            "severity": "LOW",
            "confidence": 60,
            "description": f"Found {len(emails)} email address(es) embedded in sample",
            "evidence": [{"type": "email", "value": e} for e in emails[:5]],
            "tags": ["email", "ioc"],
            "source": "triage-universal",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    # Filesystem path finding
    filepaths = iocs.get("filepath", [])
    if filepaths:
        findings.append({
            "id": "triage-filesystem-paths",
            "title": "Filesystem Paths Detected",
            "severity": "LOW",
            "confidence": 55,
            "description": f"Found {len(filepaths)} embedded filesystem path(s)",
            "evidence": [{"type": "filepath", "value": p} for p in filepaths[:5]],
            "tags": ["filesystem", "ioc"],
            "source": "triage-universal",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    # Registry key finding
    reg_keys = iocs.get("registry", [])
    if reg_keys:
        findings.append({
            "id": "triage-registry-keys",
            "title": "Registry Key References Detected",
            "severity": "LOW",
            "confidence": 60,
            "description": f"Found {len(reg_keys)} Windows registry key reference(s)",
            "evidence": [{"type": "registry", "value": k} for k in reg_keys[:5]],
            "tags": ["registry", "persistence"],
            "source": "triage-universal",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    return sorted(findings, key=lambda f: f["id"])


# generate_ioc_records is replaced by make_ioc_records from the ioc module.


def run_analysis(input_data: dict) -> dict:
    """
    Run triage analysis on sample.

    Args:
        input_data: Analysis input dictionary

    Returns:
        Analysis report dictionary
    """
    logger.info("Starting triage analysis")

    analysis_start = datetime.now(timezone.utc)

    # Extract input fields
    sample_sha256 = input_data["sample_sha256"]
    tenant_id = input_data["tenant_id"]
    pipeline_name = input_data.get("metadata", {}).get("pipeline_name", "triage")
    pipeline_hash = input_data.get("metadata", {}).get("pipeline_hash", "")
    filename = input_data.get("metadata", {}).get("filename")

    # Read local sample
    if not SAMPLE_PATH.exists():
        raise FileNotFoundError(f"Sample file not found: {SAMPLE_PATH}")

    logger.info(f"Reading sample from {SAMPLE_PATH}")
    with open(SAMPLE_PATH, "rb") as f:
        sample_data = f.read()

    # Verify hash
    if not verify_sha256(sample_data, sample_sha256):
        actual_hash = hashlib.sha256(sample_data).hexdigest()
        logger.error(f"Hash mismatch: expected {sample_sha256}, got {actual_hash}")
        raise ValueError(f"Sample hash mismatch: expected {sample_sha256}, got {actual_hash}")

    logger.info(f"Sample hash verified: {sample_sha256}")

    # Compute hashes
    md5_hash = hashlib.md5(sample_data).hexdigest()
    sha1_hash = hashlib.sha1(sample_data).hexdigest()
    sha512_hash = hashlib.sha512(sample_data).hexdigest()

    # Extract strings
    logger.info("Extracting strings")
    strings = extract_strings(sample_data)

    # Compute entropy
    logger.info("Computing entropy")
    entropies = compute_chunk_entropies(sample_data)

    # Detect file type from magic bytes (with filename as fallback hint)
    file_type = detect_file_type(sample_data, filename)

    # Calculate average entropy
    avg_entropy = sum(e["entropy"] for e in entropies) / len(entropies) if entropies else 0

    # Extract IOCs (join strings into a single text blob for the library)
    logger.info("Extracting IOCs")
    iocs = extract_iocs("\n".join(strings))

    # Generate structural findings (entropy, IOCs, etc.)
    logger.info("Generating findings")
    findings = generate_findings(sample_data, iocs, entropies)

    # Evasion heuristics on extracted strings (works for any file type; most
    # signals trigger only on Windows PE indicator strings)
    logger.info("Running evasion heuristics")
    evasion_profile  = build_evasion_profile(imports=[], strings=strings)
    evasion_findings = evasion_profile_to_findings(evasion_profile, source="triage-universal")
    if evasion_findings:
        findings = sorted(findings + evasion_findings, key=lambda f: f["id"])

    # Calculate verdict and score (evasion score feeds into verdict)
    evasion_score = evasion_profile.score
    score = 0
    if any(f["severity"] == "CRITICAL" for f in findings):
        score = 95
    elif any(f["severity"] == "HIGH" for f in findings):
        score = max(75, evasion_score)
    elif any(f["severity"] == "MEDIUM" for f in findings):
        score = max(50, evasion_score)
    elif findings:
        score = max(25, evasion_score)
    elif evasion_score > 0:
        score = evasion_score

    verdict = "unknown"
    if score >= 75:
        verdict = "malicious"
    elif score >= 50:
        verdict = "suspicious"
    elif score > 0:
        verdict = "benign"

    # Generate, deduplicate, and sort IOC records
    ioc_records = sort_ioc_records(
        deduplicate_ioc_records(make_ioc_records(iocs, sample_sha256))
    )

    # Compute config hash
    config_data = json.dumps({
        "chunk_size": CHUNK_SIZE,
        "max_strings": MAX_STRINGS,
        "high_entropy_threshold": HIGH_ENTROPY_THRESHOLD,
    }, sort_keys=True)
    config_hash = hashlib.sha256(config_data.encode()).hexdigest()

    analysis_end = datetime.now(timezone.utc)

    # Build report
    report = {
        "schema_version": "1.0.0",
        "sample_sha256": sample_sha256,
        "tenant_id": tenant_id,
        "file_type": file_type,
        "avg_entropy": round(avg_entropy, 4),
        "hashes": {
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sample_sha256,
            "sha512": sha512_hash,
        },
        "summary": {
            "verdict": verdict,
            "score": score,
            "evasion_score": evasion_score,
            "evasion_categories": sorted({i.category for i in evasion_profile.indicators}),
        },
        "findings": findings,
        "iocs": ioc_records,
        "artifacts": [
            {
                "type": "strings",
                "path": "artifacts/strings.txt",
                "sha256": hashlib.sha256("\n".join(strings).encode()).hexdigest(),
                "mime": "text/plain",
                "size_bytes": sum(len(s) for s in strings),
                "produced_by": "triage-universal",
            }
        ],
        "provenance": {
            "pipeline_name": pipeline_name,
            "pipeline_hash": pipeline_hash,
            "engines": [
                {
                    "name": "triage-universal",
                    "version": "0.1.0",
                }
            ],
            "config_hash": config_hash,
            "deterministic_run": True,
        },
        "timestamps": {
            "analysis_start": analysis_start.isoformat(),
            "analysis_end": analysis_end.isoformat(),
        },
    }

    logger.info(f"Analysis complete: verdict={verdict}, score={score}")
    return report


def write_artifacts(strings: list[str]) -> None:
    """Write artifacts to output directory."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    # Write strings file
    strings_path = ARTIFACTS_DIR / "strings.txt"
    with open(strings_path, "w", encoding="utf-8", errors="replace") as f:
        for string in strings:
            f.write(string + "\n")

    logger.info(f"Wrote {len(strings)} strings to {strings_path}")


def main() -> int:
    """Main entry point."""
    logger.info("Triage Universal Analyzer starting")

    # Check input file
    if not INPUT_PATH.exists():
        logger.error(f"Input file not found: {INPUT_PATH}")
        return 1

    # Read input
    with open(INPUT_PATH, "r") as f:
        input_data = json.load(f)

    logger.info(f"Processing sample: {input_data['sample_sha256']}")

    try:
        # Run analysis
        report = run_analysis(input_data)

        # Ensure output directory exists
        OUT_DIR.mkdir(parents=True, exist_ok=True)

        # Write report
        report_path = OUT_DIR / "report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Report written to {report_path}")

        # Write artifacts
        # We need to read the sample data to extract strings
        with open(SAMPLE_PATH, "rb") as f:
            sample_data = f.read()
        strings = extract_strings(sample_data)
        write_artifacts(strings)

        logger.info("Analysis completed successfully")
        return 0

    except Exception as e:
        logger.exception(f"Analysis failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
