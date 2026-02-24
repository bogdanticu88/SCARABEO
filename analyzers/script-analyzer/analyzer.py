"""Script Analyzer - Static analysis of script files."""

import base64
import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='{"timestamp":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}')
logger = logging.getLogger(__name__)

WORK_DIR = Path("/work")
INPUT_PATH = WORK_DIR / "input.json"
OUT_DIR = WORK_DIR / "output"
ARTIFACTS_DIR = OUT_DIR / "artifacts"
SAMPLE_PATH = WORK_DIR / "sample"


def detect_script_type(data: bytes, filename: str) -> str:
    """Detect script type."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = data.decode("latin-1", errors="replace")

    if text.startswith("#!"):
        first_line = text.split("\n")[0].lower()
        if "python" in first_line:
            return "python"
        if "bash" in first_line or "sh" in first_line:
            return "bash"
        if "perl" in first_line:
            return "perl"
        if "ruby" in first_line:
            return "ruby"
        if "node" in first_line or "js" in first_line:
            return "javascript"

    ext = Path(filename).suffix.lower()
    mapping = {
        ".py": "python", ".pyw": "python",
        ".js": "javascript", ".jsx": "javascript",
        ".ps1": "powershell", ".psm1": "powershell",
        ".vbs": "vbscript", ".vbe": "vbscript",
        ".bat": "batch", ".cmd": "batch",
        ".sh": "bash", ".bash": "bash",
        ".pl": "perl", ".pm": "perl",
        ".rb": "ruby",
        ".lua": "lua",
        ".php": "php",
    }
    return mapping.get(ext, "unknown")


def extract_iocs(text: str) -> dict:
    """Extract IOCs from script."""
    iocs = {"urls": [], "domains": [], "ips": [], "emails": []}

    url_pattern = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)
    domain_pattern = re.compile(r'\b[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}\b')
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    email_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')

    seen = {"urls": set(), "domains": set(), "ips": set(), "emails": set()}

    for match in url_pattern.finditer(text):
        url = match.group()
        if url not in seen["urls"]:
            seen["urls"].add(url)
            iocs["urls"].append(url)

    for match in domain_pattern.finditer(text):
        domain = match.group()
        if domain not in seen["domains"] and not any(domain in u for u in seen["urls"]):
            seen["domains"].add(domain)
            iocs["domains"].append(domain)

    for match in ip_pattern.finditer(text):
        ip = match.group()
        if ip not in seen["ips"]:
            seen["ips"].add(ip)
            iocs["ips"].append(ip)

    for match in email_pattern.finditer(text):
        email = match.group()
        if email not in seen["emails"]:
            seen["emails"].add(email)
            iocs["emails"].append(email)

    for key in iocs:
        iocs[key].sort()

    return iocs


def detect_obfuscation(text: str) -> list[dict]:
    """Detect obfuscation markers."""
    markers = []

    # Base64 blobs (long base64-like strings)
    base64_pattern = re.compile(r'[A-Za-z0-9+/=]{50,}')
    for match in base64_pattern.finditer(text):
        markers.append({"type": "base64_blob", "offset": match.start(), "length": len(match.group())})

    # CharCode patterns (JavaScript)
    charcode_pattern = re.compile(r'String\.fromCharCode|\.fromCharCode')
    for match in charcode_pattern.finditer(text):
        markers.append({"type": "fromCharCode", "offset": match.start()})

    # Long concatenation chains
    concat_pattern = re.compile(r'(\+[^+]){5,}')
    for match in concat_pattern.finditer(text):
        markers.append({"type": "concat_chain", "offset": match.start(), "length": len(match.group())})

    # PowerShell encoded commands
    encoded_cmd_pattern = re.compile(r'-EncodedCommand\s+[A-Za-z0-9+/=]+|-e\s+[A-Za-z0-9+/=]{20,}', re.IGNORECASE)
    for match in encoded_cmd_pattern.finditer(text):
        markers.append({"type": "encoded_command", "offset": match.start()})

    # Eval usage
    eval_pattern = re.compile(r'\beval\s*\(')
    for match in eval_pattern.finditer(text):
        markers.append({"type": "eval_usage", "offset": match.start()})

    return markers


def generate_findings(script_type: str, iocs: dict, obfuscation: list[dict], text: str = "") -> list[dict]:
    """Generate findings."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    if iocs["urls"] or iocs["domains"]:
        findings.append({
            "id": f"script-network-{len(findings)}",
            "title": "Network Indicators in Script",
            "severity": "MEDIUM",
            "confidence": 70,
            "description": f"Found {len(iocs['urls'])} URLs and {len(iocs['domains'])} domains",
            "evidence": [{"type": "url", "value": u} for u in iocs["urls"][:5]] + [{"type": "domain", "value": d} for d in iocs["domains"][:5]],
            "tags": ["network", "ioc"],
            "source": "script-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    if obfuscation:
        obf_types = list(set(o["type"] for o in obfuscation))
        findings.append({
            "id": f"script-obfuscation-{len(findings)}",
            "title": "Obfuscation Markers Detected",
            "severity": "MEDIUM",
            "confidence": 60,
            "description": f"Found {len(obfuscation)} obfuscation markers: {', '.join(obf_types)}",
            "evidence": [{"type": "marker", "value": o["type"]} for o in obfuscation[:10]],
            "tags": ["obfuscation", "evasion"],
            "source": "script-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    # PowerShell-specific checks
    if script_type == "powershell":
        findings.append({
            "id": f"script-powershell-{len(findings)}",
            "title": "PowerShell Script Detected",
            "severity": "LOW",
            "confidence": 90,
            "description": "PowerShell scripts can execute system commands and access sensitive resources",
            "evidence": [{"type": "script_type", "value": "powershell"}],
            "tags": ["powershell"],
            "source": "script-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    return findings


def run_analysis(input_data: dict) -> dict:
    """Run script analysis."""
    logger.info("Starting script analysis")

    sample_sha256 = input_data["sample_sha256"]
    filename = input_data["sample"].get("filename", "unknown")

    if not SAMPLE_PATH.exists():
        raise FileNotFoundError(f"Sample file not found: {SAMPLE_PATH}")

    with open(SAMPLE_PATH, "rb") as f:
        sample_data = f.read()

    actual_hash = hashlib.sha256(sample_data).hexdigest()
    if actual_hash.lower() != sample_sha256.lower():
        raise ValueError(f"Hash mismatch: expected {sample_sha256}, got {actual_hash}")

    try:
        text = sample_data.decode("utf-8", errors="replace")
    except Exception:
        text = sample_data.decode("latin-1", errors="replace")

    script_type = detect_script_type(sample_data, filename)
    iocs = extract_iocs(text)
    obfuscation = detect_obfuscation(text)
    findings = generate_findings(script_type, iocs, obfuscation, text)

    script_summary = {
        "file_type": "script",
        "script_type": script_type,
        "size_bytes": len(sample_data),
        "line_count": len(text.splitlines()),
        "character_count": len(text),
        "obfuscation_markers": obfuscation,
        "ioc_counts": {k: len(v) for k, v in iocs.items()},
    }

    ioc_records = []
    for url in iocs["urls"]:
        ioc_records.append({"type": "url", "value": url, "normalized": url.lower(), "confidence": 70, "first_seen_in": sample_sha256, "tags": ["network"]})
    for domain in iocs["domains"]:
        ioc_records.append({"type": "domain", "value": domain, "normalized": domain.lower(), "confidence": 70, "first_seen_in": sample_sha256, "tags": ["network"]})
    for ip in iocs["ips"]:
        ioc_records.append({"type": "ip", "value": ip, "normalized": ip, "confidence": 60, "first_seen_in": sample_sha256, "tags": ["network"]})
    for email in iocs["emails"]:
        ioc_records.append({"type": "email", "value": email, "normalized": email.lower(), "confidence": 50, "first_seen_in": sample_sha256, "tags": ["contact"]})

    report = {
        "schema_version": "1.0.0",
        "analyzer_name": "script-analyzer",
        "analyzer_version": "0.1.0",
        "findings": sorted(findings, key=lambda f: f["id"]),
        "iocs": ioc_records,
        "artifacts": [{"type": "script_summary", "path": "artifacts/script_summary.json", "produced_by": "script-analyzer"},
                      {"type": "iocs", "path": "artifacts/iocs.txt", "produced_by": "script-analyzer"}],
        "metadata": script_summary,
    }

    logger.info(f"Script analysis complete: {len(findings)} findings, type={script_type}")
    return report


def write_artifacts(script_summary: dict, iocs: dict) -> None:
    """Write artifacts."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    with open(ARTIFACTS_DIR / "script_summary.json", "w") as f:
        json.dump(script_summary, f, indent=2)

    with open(ARTIFACTS_DIR / "iocs.txt", "w") as f:
        for ioc_type in ["urls", "domains", "ips", "emails"]:
            for ioc in iocs.get(ioc_type, []):
                f.write(f"{ioc_type}: {ioc}\n")

    logger.info(f"Wrote artifacts to {ARTIFACTS_DIR}")


def main() -> int:
    """Main entry point."""
    logger.info("Script Analyzer starting")

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

        # Extract IOCs again for artifacts to avoid needing to pass text around
        # Or we could just pass extract_iocs from report, but report iocs are normalized
        # Let's re-read for simplicity as in other analyzers
        with open(SAMPLE_PATH, "rb") as f:
            sample_data = f.read()
        try:
            text = sample_data.decode("utf-8", errors="replace")
        except Exception:
            text = sample_data.decode("latin-1", errors="replace")

        write_artifacts(report["metadata"], extract_iocs(text))

        logger.info("Script analysis completed successfully")
        return 0
    except Exception as e:
        logger.exception(f"Script analysis failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
