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


def extract_iocs(strings: list[str]) -> dict:
    """
    Extract IOCs from strings.

    Args:
        strings: List of extracted strings

    Returns:
        Dictionary of IOC lists
    """
    iocs = {
        "urls": [],
        "domains": [],
        "ips": [],
        "emails": [],
    }

    # URL pattern
    url_pattern = re.compile(
        r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
        re.IGNORECASE
    )

    # Domain pattern
    domain_pattern = re.compile(
        r'\b[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}\b'
    )

    # IP pattern
    ip_pattern = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )

    # Email pattern
    email_pattern = re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    )

    seen_urls = set()
    seen_domains = set()
    seen_ips = set()
    seen_emails = set()

    for string in strings:
        # Extract URLs
        for match in url_pattern.finditer(string):
            url = match.group()
            if url not in seen_urls:
                seen_urls.add(url)
                iocs["urls"].append(url)

        # Extract domains (excluding URLs)
        for match in domain_pattern.finditer(string):
            domain = match.group()
            # Skip if part of URL
            if f"http://{domain}" in seen_urls or f"https://{domain}" in seen_urls:
                continue
            if domain not in seen_domains:
                seen_domains.add(domain)
                iocs["domains"].append(domain)

        # Extract IPs
        for match in ip_pattern.finditer(string):
            ip = match.group()
            if ip not in seen_ips:
                seen_ips.add(ip)
                iocs["ips"].append(ip)

        # Extract emails
        for match in email_pattern.finditer(string):
            email = match.group()
            if email not in seen_emails:
                seen_emails.add(email)
                iocs["emails"].append(email)

    # Sort for deterministic output
    iocs["urls"].sort()
    iocs["domains"].sort()
    iocs["ips"].sort()
    iocs["emails"].sort()

    return iocs


def normalize_ioc(ioc_type: str, value: str) -> str:
    """Normalize IOC value."""
    if ioc_type == "domain":
        return value.lower()
    elif ioc_type == "email":
        return value.lower()
    elif ioc_type == "url":
        # Lowercase scheme and domain
        parts = value.split("://", 1)
        if len(parts) == 2:
            return parts[0].lower() + "://" + parts[1].split("/", 2)[0].lower() + "/" + "/".join(parts[1].split("/")[1:])
        return value.lower()
    return value


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

    Args:
        data: Sample bytes
        iocs: Extracted IOCs
        entropies: Chunk entropy data

    Returns:
        List of findings
    """
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    # High entropy finding
    high_entropy_chunks = [e for e in entropies if e["entropy"] > HIGH_ENTROPY_THRESHOLD]
    if high_entropy_chunks:
        findings.append({
            "id": f"finding-entropy-{len(findings)}",
            "title": "High Entropy Content Detected",
            "severity": "MEDIUM",
            "confidence": 75,
            "description": f"Found {len(high_entropy_chunks)} chunks with entropy above {HIGH_ENTROPY_THRESHOLD}, indicating possible encryption or packing",
            "evidence": [
                {
                    "type": "entropy",
                    "value": f"offset={e['offset']},entropy={e['entropy']}",
                }
                for e in high_entropy_chunks[:5]  # Limit evidence
            ],
            "tags": ["encryption", "packing", "entropy"],
            "source": "triage-universal",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    # Network indicators finding
    if iocs["urls"] or iocs["domains"]:
        evidence = []
        for url in iocs["urls"][:5]:
            evidence.append({"type": "url", "value": url})
        for domain in iocs["domains"][:5]:
            evidence.append({"type": "domain", "value": domain})

        findings.append({
            "id": f"finding-network-{len(findings)}",
            "title": "Network Indicators Detected",
            "severity": "HIGH",
            "confidence": 80,
            "description": f"Found {len(iocs['urls'])} URLs and {len(iocs['domains'])} domains embedded in sample",
            "evidence": evidence,
            "tags": ["network", "ioc", "c2"],
            "source": "triage-universal",
            "references": ["https://attack.mitre.org/techniques/T1071/"],
            "affected_objects": [],
            "created_at": now,
        })

    # Email indicators finding
    if iocs["emails"]:
        findings.append({
            "id": f"finding-email-{len(findings)}",
            "title": "Email Addresses Detected",
            "severity": "LOW",
            "confidence": 60,
            "description": f"Found {len(iocs['emails'])} email addresses embedded in sample",
            "evidence": [
                {"type": "email", "value": email}
                for email in iocs["emails"][:5]
            ],
            "tags": ["email", "ioc"],
            "source": "triage-universal",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    return findings


def generate_ioc_records(iocs: dict, first_seen_in: str) -> list[dict]:
    """
    Generate IOC records for report.

    Args:
        iocs: Extracted IOCs
        first_seen_in: Sample identifier

    Returns:
        List of IOC records
    """
    records = []

    for url in iocs["urls"]:
        records.append({
            "type": "url",
            "value": url,
            "normalized": normalize_ioc("url", url),
            "confidence": 70,
            "context": "Extracted from sample strings",
            "first_seen_in": first_seen_in,
            "tags": ["network"],
        })

    for domain in iocs["domains"]:
        records.append({
            "type": "domain",
            "value": domain,
            "normalized": normalize_ioc("domain", domain),
            "confidence": 70,
            "context": "Extracted from sample strings",
            "first_seen_in": first_seen_in,
            "tags": ["network"],
        })

    for ip in iocs["ips"]:
        records.append({
            "type": "ip",
            "value": ip,
            "normalized": ip,
            "confidence": 60,
            "context": "Extracted from sample strings",
            "first_seen_in": first_seen_in,
            "tags": ["network"],
        })

    for email in iocs["emails"]:
        records.append({
            "type": "email",
            "value": email,
            "normalized": normalize_ioc("email", email),
            "confidence": 50,
            "context": "Extracted from sample strings",
            "first_seen_in": first_seen_in,
            "tags": ["contact"],
        })

    return records


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

    # Calculate average entropy
    avg_entropy = sum(e["entropy"] for e in entropies) / len(entropies) if entropies else 0

    # Extract IOCs
    logger.info("Extracting IOCs")
    iocs = extract_iocs(strings)

    # Generate findings
    logger.info("Generating findings")
    findings = generate_findings(sample_data, iocs, entropies)

    # Calculate verdict and score
    score = 0
    if any(f["severity"] == "CRITICAL" for f in findings):
        score = 95
    elif any(f["severity"] == "HIGH" for f in findings):
        score = 75
    elif any(f["severity"] == "MEDIUM" for f in findings):
        score = 50
    elif findings:
        score = 25

    verdict = "unknown"
    if score >= 75:
        verdict = "malicious"
    elif score >= 50:
        verdict = "suspicious"
    elif score > 0:
        verdict = "benign"

    # Generate IOC records
    ioc_records = generate_ioc_records(iocs, sample_sha256)

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
        "file_type": "unknown",
        "hashes": {
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sample_sha256,
            "sha512": sha512_hash,
        },
        "summary": {
            "verdict": verdict,
            "score": score,
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
