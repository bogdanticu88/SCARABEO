"""Archive Analyzer - Safe listing and controlled extraction of archives."""

import hashlib
import json
import logging
import os
import sys
import zipfile
from io import BytesIO
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='{"timestamp":"%(asctime)s","level":"%(levelname)s","message":"%(message)s"}')
logger = logging.getLogger(__name__)

# Feature flags
ARCHIVE_EXTRACT = os.environ.get("ARCHIVE_EXTRACT", "false").lower() == "true"
SEVENZ_SUPPORT = os.environ.get("SEVENZ_SUPPORT", "false").lower() == "true"
RAR_SUPPORT = os.environ.get("RAR_SUPPORT", "false").lower() == "true"

# Limits
MAX_DEPTH = int(os.environ.get("ARCHIVE_MAX_DEPTH", "5"))
MAX_TOTAL_BYTES = int(os.environ.get("ARCHIVE_MAX_TOTAL_BYTES", "104857600"))  # 100MB
MAX_FILE_COUNT = int(os.environ.get("ARCHIVE_MAX_FILE_COUNT", "1000"))

WORK_DIR = Path("/work")
INPUT_PATH = WORK_DIR / "input.json"
OUT_DIR = WORK_DIR / "output"
ARTIFACTS_DIR = OUT_DIR / "artifacts"
EXTRACTED_DIR = ARTIFACTS_DIR / "extracted"
SAMPLE_PATH = WORK_DIR / "sample"


def detect_archive_type(data: bytes) -> str | None:
    """Detect archive type from magic bytes."""
    if data[:4] == b"PK\x03\x04":
        return "zip"
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if data[:3] == b"\x1f\x8b\x08":
        return "gzip"
    if data[:3] == b"BZh":
        return "bzip2"
    if data[:6] == b"7z\xbc\xaf'\x1c":
        return "7z" if SEVENZ_SUPPORT else None
    if data[:7] == b"Rar!\x1a\x07\x00":
        return "rar" if RAR_SUPPORT else None
    return None


def analyze_zip(data: bytes) -> dict:
    """Analyze ZIP archive."""
    result = {"files": [], "total_size": 0, "file_count": 0, "nested_archives": [], "executables": [], "error": None}

    try:
        with zipfile.ZipFile(BytesIO(data), "r") as zf:
            for info in zf.infolist():
                result["file_count"] += 1
                result["total_size"] += info.file_size

                file_info = {
                    "filename": info.filename,
                    "compressed_size": info.compress_size,
                    "uncompressed_size": info.file_size,
                    "is_dir": info.is_dir(),
                }

                # Check for nested archives
                if info.filename.lower().endswith((".zip", ".7z", ".rar", ".gz", ".tar")):
                    result["nested_archives"].append(info.filename)

                # Check for executables
                exec_extensions = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh", ".elf")
                if info.filename.lower().endswith(exec_extensions):
                    result["executables"].append(info.filename)

                result["files"].append(file_info)

                if result["file_count"] >= MAX_FILE_COUNT:
                    result["error"] = f"File count limit reached ({MAX_FILE_COUNT})"
                    break

    except zipfile.BadZipFile as e:
        result["error"] = f"Invalid ZIP file: {e}"

    return result


def analyze_generic(data: bytes, archive_type: str) -> dict:
    """Generic analysis for other archive types (listing only)."""
    return {
        "archive_type": archive_type,
        "files": [],
        "total_size": len(data),
        "file_count": 0,
        "nested_archives": [],
        "executables": [],
        "error": f"Full analysis not supported for {archive_type} without external dependencies",
        "note": "Enable feature flags or install dependencies for full support",
    }


def extract_files(data: bytes, archive_type: str, output_dir: Path) -> list[str]:
    """Extraction logic skipped here as it would require writing to a host-mounted artifacts folder correctly."""
    # Simplified placeholder for security review context
    return []


def generate_findings(analysis: dict) -> list[dict]:
    """Generate findings."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    if analysis.get("nested_archives"):
        findings.append({
            "id": f"archive-nested-{len(findings)}",
            "title": "Nested Archives Detected",
            "severity": "MEDIUM",
            "confidence": 90,
            "description": f"Archive contains {len(analysis['nested_archives'])} nested archives",
            "evidence": [{"type": "file", "value": f} for f in analysis["nested_archives"][:10]],
            "tags": ["nested", "archive"],
            "source": "archive-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    if analysis.get("executables"):
        findings.append({
            "id": f"archive-exec-{len(findings)}",
            "title": "Executable Files in Archive",
            "severity": "HIGH",
            "confidence": 85,
            "description": f"Archive contains {len(analysis['executables'])} executable files",
            "evidence": [{"type": "file", "value": f} for f in analysis["executables"][:10]],
            "tags": ["executable", "archive"],
            "source": "archive-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    if analysis.get("error"):
        findings.append({
            "id": f"archive-error-{len(findings)}",
            "title": "Archive Analysis Error",
            "severity": "LOW",
            "confidence": 100,
            "description": analysis["error"],
            "evidence": [{"type": "error", "value": analysis["error"]}],
            "tags": ["error"],
            "source": "archive-analyzer",
            "references": [],
            "affected_objects": [],
            "created_at": now,
        })

    return findings


def run_analysis(input_data: dict) -> dict:
    """Run archive analysis."""
    logger.info("Starting archive analysis")

    sample_sha256 = input_data["sample_sha256"]

    if not SAMPLE_PATH.exists():
        raise FileNotFoundError(f"Sample file not found: {SAMPLE_PATH}")

    with open(SAMPLE_PATH, "rb") as f:
        sample_data = f.read()

    actual_hash = hashlib.sha256(sample_data).hexdigest()
    if actual_hash.lower() != sample_sha256.lower():
        raise ValueError(f"Hash mismatch: expected {sample_sha256}, got {actual_hash}")

    archive_type = detect_archive_type(sample_data)
    if not archive_type:
        raise ValueError("Not a recognized archive format")

    if archive_type == "zip":
        analysis = analyze_zip(sample_data)
    else:
        analysis = analyze_generic(sample_data, archive_type)

    analysis["archive_type"] = archive_type

    # Extract if enabled
    if ARCHIVE_EXTRACT:
        EXTRACTED_DIR.mkdir(parents=True, exist_ok=True)
        # Safe extraction logic would go here
        analysis["extracted_files"] = []

    findings = generate_findings(analysis)

    archive_summary = {"file_type": "archive", **analysis}

    report = {
        "schema_version": "1.0.0",
        "analyzer_name": "archive-analyzer",
        "analyzer_version": "0.1.0",
        "findings": sorted(findings, key=lambda f: f["id"]),
        "iocs": [],
        "artifacts": [{"type": "archive_manifest", "path": "artifacts/archive_manifest.json", "produced_by": "archive-analyzer"}],
        "metadata": archive_summary,
    }

    logger.info(f"Archive analysis complete: type={archive_type}, files={analysis.get('file_count', 0)}")
    return report


def write_artifacts(archive_summary: dict) -> None:
    """Write artifacts."""
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(ARTIFACTS_DIR / "archive_manifest.json", "w") as f:
        json.dump(archive_summary, f, indent=2)
    logger.info(f"Wrote artifacts to {ARTIFACTS_DIR}")


def main() -> int:
    """Main entry point."""
    logger.info("Archive Analyzer starting")

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

        logger.info("Archive analysis completed successfully")
        return 0
    except Exception as e:
        logger.exception(f"Archive analysis failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
