"""Document Analyzer - Static analysis of document files (OLE/OOXML)."""

import hashlib
import json
import logging
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from io import BytesIO

logging.basicConfig(level=logging.INFO, format='{"timestamp":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}')
logger = logging.getLogger(__name__)

WORK_DIR = Path("/work")
INPUT_PATH = WORK_DIR / "input.json"
OUT_DIR = WORK_DIR / "output"
ARTIFACTS_DIR = OUT_DIR / "artifacts"
SAMPLE_PATH = WORK_DIR / "sample"

# OLE magic bytes
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def is_ole_file(data: bytes) -> bool:
    """Check if data is OLE compound document."""
    return data[:8] == OLE_MAGIC


def is_ooxml_file(data: bytes) -> bool:
    """Check if data is OOXML (ZIP-based)."""
    return data[:4] == b"PK\x03\x04"


def analyze_ooxml(data: bytes) -> dict:
    """Analyze OOXML document."""
    result = {"macros_present": False, "embedded_objects": [], "external_links": [], "relationships": []}

    try:
        with zipfile.ZipFile(BytesIO(data), "r") as zf:
            names = zf.namelist()

            # Check for macros (vbaProject.bin)
            if any("vbaProject.bin" in n for n in names):
                result["macros_present"] = True

            # Check for embedded objects
            if any("embeddings" in n.lower() or "object" in n.lower() for n in names):
                result["embedded_objects"] = [n for n in names if "embeddings" in n.lower() or "object" in n.lower()]

            # Check relationships for external links
            rel_files = [n for n in names if n.endswith(".rels")]
            for rel_file in rel_files:
                try:
                    rel_content = zf.read(rel_file).decode("utf-8", errors="replace")
                    # Look for external links
                    import re
                    links = re.findall(r'Target="([^"]+)"', rel_content)
                    for link in links:
                        if link.startswith("http://") or link.startswith("https://"):
                            result["external_links"].append(link)
                except Exception:
                    pass

            result["relationships"] = names

    except zipfile.BadZipFile:
        result["error"] = "Invalid OOXML file"

    return result


def analyze_ole(data: bytes) -> dict:
    """Analyze OLE document (simplified, no external deps)."""
    result = {"macros_present": None, "embedded_objects": [], "streams": []}

    # Basic OLE parsing without olefile dependency
    # Look for common stream names in the binary
    text = data.decode("latin-1", errors="replace")

    if "VBA" in text or "Macros" in text:
        result["macros_present"] = True

    # Look for embedded object markers
    if "Embed" in text or "Obj" in text:
        result["embedded_objects"] = ["detected_by_pattern"]

    result["streams"] = ["basic_ole_analysis_only"]

    return result


def generate_findings(doc_type: str, analysis: dict) -> list[dict]:
    """Generate findings."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    if analysis.get("macros_present"):
        findings.append({
            "id": f"doc-macros-{len(findings)}",
            "title": "Macros Present in Document",
            "severity": "MEDIUM",
            "confidence": 80,
            "description": "Document contains macros which can execute arbitrary code",
            "evidence": [{"type": "feature", "value": "vbaProject.bin present"}],
            "tags": ["macros", "vba"],
            "source": "doc-analyzer",
            "references": ["https://attack.mitre.org/techniques/T1566/"],
            "affected_objects": [],
            "created_at": now,
        })

    if analysis.get("embedded_objects"):
        findings.append({
            "id": f"doc-embedded-{len(findings)}",
            "title": "Embedded Objects Detected",
            "severity": "MEDIUM",
            "confidence": 70,
            "description": f"Document contains {len(analysis['embedded_objects'])} embedded objects",
            "evidence": [{"type": "object", "value": str(o)} for o in analysis["embedded_objects"][:5]],
            "tags": ["embedded", "ole"],
            "source": "doc-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    if analysis.get("external_links"):
        findings.append({
            "id": f"doc-external-{len(findings)}",
            "title": "External Links in Document",
            "severity": "LOW",
            "confidence": 75,
            "description": f"Document references {len(analysis['external_links'])} external URLs",
            "evidence": [{"type": "url", "value": link} for link in analysis["external_links"][:5]],
            "tags": ["network", "external"],
            "source": "doc-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    return findings


def run_analysis(input_data: dict) -> dict:
    """Run document analysis."""
    logger.info("Starting document analysis")

    sample_sha256 = input_data["sample_sha256"]

    if not SAMPLE_PATH.exists():
        raise FileNotFoundError(f"Sample file not found: {SAMPLE_PATH}")

    with open(SAMPLE_PATH, "rb") as f:
        sample_data = f.read()

    actual_hash = hashlib.sha256(sample_data).hexdigest()
    if actual_hash.lower() != sample_sha256.lower():
        raise ValueError(f"Hash mismatch: expected {sample_sha256}, got {actual_hash}")

    if is_ole_file(sample_data):
        doc_type = "ole"
        analysis = analyze_ole(sample_data)
    elif is_ooxml_file(sample_data):
        doc_type = "ooxml"
        analysis = analyze_ooxml(sample_data)
    else:
        doc_type = "unknown"
        analysis = {"error": "Unknown document format"}

    findings = generate_findings(doc_type, analysis)

    doc_summary = {"file_type": "document", "doc_type": doc_type, "size_bytes": len(sample_data), **analysis}

    report = {
        "schema_version": "1.0.0",
        "analyzer_name": "doc-analyzer",
        "analyzer_version": "0.1.0",
        "findings": sorted(findings, key=lambda f: f["id"]),
        "iocs": [],
        "artifacts": [{"type": "doc_summary", "path": "artifacts/doc_summary.json", "produced_by": "doc-analyzer"}],
        "metadata": doc_summary,
    }

    logger.info(f"Document analysis complete: type={doc_type}, findings={len(findings)}")
    return report


def write_artifacts(doc_summary: dict) -> None:
    """Write artifacts."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(ARTIFACTS_DIR / "doc_summary.json", "w") as f:
        json.dump(doc_summary, f, indent=2)
    logger.info(f"Wrote artifacts to {ARTIFACTS_DIR}")


def main() -> int:
    """Main entry point."""
    logger.info("Document Analyzer starting")

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

        logger.info("Document analysis completed successfully")
        return 0
    except Exception as e:
        logger.exception(f"Document analysis failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
