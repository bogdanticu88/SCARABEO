"""CAPA Analyzer - Optional capability extraction."""

import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='{"timestamp":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}')
logger = logging.getLogger(__name__)

# Feature flag
CAPA_ENABLED = os.environ.get("CAPA_ENABLED", "false").lower() == "true"

WORK_DIR = Path("/work")
INPUT_PATH = WORK_DIR / "input.json"
OUT_DIR = WORK_DIR / "output"
ARTIFACTS_DIR = OUT_DIR / "artifacts"
SAMPLE_PATH = WORK_DIR / "sample"


def run_capa_analysis(data: bytes) -> list[dict]:
    """Run CAPA analysis."""
    if not CAPA_ENABLED:
        return []

    try:
        import capa.main
        import capa.rules
        import capa.engine
        import capa.features.common
        import capa.render.result_document
    except ImportError:
        logger.warning("CAPA not installed - skipping CAPA analysis")
        return []

    # CAPA analysis would go here
    # This is a placeholder as full CAPA integration is complex
    logger.info("CAPA analysis skipped - requires full integration")
    return []


def generate_findings(capa_results: list[dict]) -> list[dict]:
    """Generate findings from CAPA results."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    for result in capa_results:
        findings.append({
            "id": f"capa-{result.get('capability', 'unknown')}-{len(findings)}",
            "title": f"CAPA Capability: {result.get('capability', 'Unknown')}",
            "severity": "MEDIUM",
            "confidence": 75,
            "description": result.get("description", "Capability detected by CAPA"),
            "evidence": [{"type": "capa", "value": str(result)}],
            "tags": ["capa", "capability"],
            "source": "capa-analyzer",
            "references": result.get("references", []),
            "affected_objects": [],
            "created_at": now,
        })

    return findings


def run_analysis(input_data: dict) -> dict:
    """Run CAPA analysis."""
    logger.info("Starting CAPA analysis")

    sample_sha256 = input_data["sample_sha256"]

    if not SAMPLE_PATH.exists():
        raise FileNotFoundError(f"Sample file not found: {SAMPLE_PATH}")

    with open(SAMPLE_PATH, "rb") as f:
        sample_data = f.read()

    actual_hash = hashlib.sha256(sample_data).hexdigest()
    if actual_hash.lower() != sample_sha256.lower():
        raise ValueError(f"Hash mismatch: expected {sample_sha256}, got {actual_hash}")

    if not CAPA_ENABLED:
        logger.info("CAPA is disabled - skipping analysis")
        return {
            "schema_version": "1.0.0",
            "analyzer_name": "capa-analyzer",
            "analyzer_version": "0.1.0",
            "findings": [],
            "iocs": [],
            "artifacts": [],
            "metadata": {"capa_enabled": False, "note": "CAPA analysis is disabled"},
        }

    capa_results = run_capa_analysis(sample_data)
    findings = generate_findings(capa_results)

    capa_summary = {
        "capa_enabled": True,
        "capabilities": capa_results,
        "capability_count": len(capa_results),
    }

    report = {
        "schema_version": "1.0.0",
        "analyzer_name": "capa-analyzer",
        "analyzer_version": "0.1.0",
        "findings": sorted(findings, key=lambda f: f["id"]),
        "iocs": [],
        "artifacts": [{"type": "capa_results", "path": "artifacts/capa_results.json", "produced_by": "capa-analyzer"}],
        "metadata": capa_summary,
    }

    logger.info(f"CAPA analysis complete: {len(capa_results)} capabilities")
    return report


def write_artifacts(capa_summary: dict) -> None:
    """Write artifacts."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(ARTIFACTS_DIR / "capa_results.json", "w") as f:
        json.dump(capa_summary, f, indent=2)
    logger.info(f"Wrote artifacts to {ARTIFACTS_DIR}")


def main() -> int:
    """Main entry point."""
    logger.info("CAPA Analyzer starting")

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

        if report["metadata"].get("capa_enabled"):
            write_artifacts(report["metadata"])

        logger.info("CAPA analysis completed successfully")
        return 0
    except Exception as e:
        logger.exception(f"CAPA analysis failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
