"""YARA Analyzer - Optional YARA rule matching."""

import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='{"timestamp":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}')
logger = logging.getLogger(__name__)

S3_ENDPOINT_URL = os.environ.get("S3_ENDPOINT_URL", "http://localhost:9000")
S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY", "scarabeo")
S3_SECRET_KEY = os.environ.get("S3_SECRET_KEY", "scarabeo_dev_password")
S3_BUCKET = os.environ.get("S3_BUCKET", "scarabeo-samples")

# Feature flag
YARA_ENABLED = os.environ.get("YARA_ENABLED", "false").lower() == "true"

WORK_DIR = Path("/work")
INPUT_PATH = WORK_DIR / "input.json"
OUT_DIR = WORK_DIR / "output"
ARTIFACTS_DIR = OUT_DIR / "artifacts"
RULES_DIR = Path("/analyzer/rules")
SAMPLE_PATH = WORK_DIR / "sample"


def load_yara_rules() -> list:
    """Load YARA rules from rules directory."""
    if not YARA_ENABLED:
        return []

    try:
        import yara
    except ImportError:
        logger.warning("YARA not installed - skipping YARA analysis")
        return []

    rules = []
    if RULES_DIR.exists():
        for rule_file in RULES_DIR.glob("*.yar"):
            try:
                rule = yara.compile(str(rule_file))
                rules.append((rule_file.name, rule))
                logger.info(f"Loaded YARA rule: {rule_file.name}")
            except Exception as e:
                logger.error(f"Failed to load YARA rule {rule_file}: {e}")

    return rules


def run_yara_analysis(data: bytes, rules: list) -> list[dict]:
    """Run YARA rules against data."""
    matches = []

    for rule_name, rule in rules:
        try:
            yara_matches = rule.match(data=data)
            for match in yara_matches:
                matches.append({
                    "rule": rule_name,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "strings": [{"identifier": s.identifier, "offset": s.offset, "data": s.data[:50]} 
                               for s in match.strings[:10]],  # Limit string data
                })
        except Exception as e:
            logger.error(f"YARA match error: {e}")

    return matches


def generate_findings(yara_matches: list[dict]) -> list[dict]:
    """Generate findings from YARA matches."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    for match in yara_matches:
        severity = "HIGH" if any(t in ["malware", "trojan", "ransomware"] for t in match.get("tags", [])) else "MEDIUM"

        findings.append({
            "id": f"yara-{match['rule']}-{len(findings)}",
            "title": f"YARA Rule Match: {match['rule']}",
            "severity": severity,
            "confidence": 85,
            "description": f"Sample matched YARA rule {match['rule']} with {len(match.get('strings', []))} string matches",
            "evidence": [{"type": "yara_string", "value": f"{s['identifier']}:{s['data'][:30]}..."} 
                        for s in match.get("strings", [])[:5]],
            "tags": ["yara"] + match.get("tags", []),
            "source": "yara-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    return findings


def run_analysis(input_data: dict) -> dict:
    """Run YARA analysis."""
    logger.info("Starting YARA analysis")

    sample_sha256 = input_data["sample_sha256"]

    if not SAMPLE_PATH.exists():
        raise FileNotFoundError(f"Sample file not found: {SAMPLE_PATH}")

    with open(SAMPLE_PATH, "rb") as f:
        sample_data = f.read()

    actual_hash = hashlib.sha256(sample_data).hexdigest()
    if actual_hash.lower() != sample_sha256.lower():
        raise ValueError(f"Hash mismatch: expected {sample_sha256}, got {actual_hash}")

    if not YARA_ENABLED:
        logger.info("YARA is disabled - skipping analysis")
        return {
            "schema_version": "1.0.0",
            "analyzer_name": "yara-analyzer",
            "analyzer_version": "0.1.0",
            "findings": [],
            "iocs": [],
            "artifacts": [],
            "metadata": {"yara_enabled": False, "note": "YARA analysis is disabled"},
        }

    rules = load_yara_rules()
    if not rules:
        return {
            "schema_version": "1.0.0",
            "analyzer_name": "yara-analyzer",
            "analyzer_version": "0.1.0",
            "findings": [],
            "iocs": [],
            "artifacts": [],
            "metadata": {"yara_enabled": True, "rules_loaded": 0, "note": "No YARA rules found"},
        }

    yara_matches = run_yara_analysis(sample_data, rules)
    findings = generate_findings(yara_matches)

    yara_summary = {
        "yara_enabled": True,
        "rules_loaded": len(rules),
        "matches": yara_matches,
        "match_count": len(yara_matches),
    }

    partial = {
        "schema_version": "1.0.0",
        "analyzer_name": "yara-analyzer",
        "analyzer_version": "0.1.0",
        "findings": sorted(findings, key=lambda f: f["id"]),
        "iocs": [],
        "artifacts": [{"type": "yara_matches", "path": "artifacts/yara_matches.json", "produced_by": "yara-analyzer"}],
        "metadata": yara_summary,
    }

    logger.info(f"YARA analysis complete: {len(yara_matches)} matches")
    return partial


def write_artifacts(yara_summary: dict) -> None:
    """Write artifacts."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(ARTIFACTS_DIR / "yara_matches.json", "w") as f:
        json.dump(yara_summary, f, indent=2)
    logger.info(f"Wrote artifacts to {ARTIFACTS_DIR}")


def main() -> int:
    """Main entry point."""
    logger.info("YARA Analyzer starting")

    if not INPUT_PATH.exists():
        logger.error(f"Input file not found: {INPUT_PATH}")
        return 1

    with open(INPUT_PATH, "r") as f:
        input_data = json.load(f)

    try:
        partial = run_analysis(input_data)
        OUT_DIR.mkdir(parents=True, exist_ok=True)

        with open(OUT_DIR / "report.json", "w") as f:
            json.dump(partial, f, indent=2)

        logger.info(f"Report written to {OUT_DIR / 'report.json'}")

        if partial["metadata"].get("yara_enabled"):
            write_artifacts(partial["metadata"])

        logger.info("YARA analysis completed successfully")
        return 0
    except Exception as e:
        logger.exception(f"YARA analysis failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
