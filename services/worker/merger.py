"""Report merger - combines partial analyzer outputs into final report."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def merge_partial_outputs(
    partials: list[dict],
    input_data: dict,
    pipeline_name: str,
    pipeline_hash: str,
) -> dict:
    """
    Merge partial analyzer outputs into final report.

    Args:
        partials: List of partial output dictionaries
        input_data: Original input data
        pipeline_name: Pipeline name
        pipeline_hash: Pipeline configuration hash

    Returns:
        Merged final report
    """
    all_findings = []
    all_iocs = []
    all_artifacts = []
    engines_run = []
    metadata = {}

    # Collect all findings, IOCs, artifacts
    for partial in partials:
        analyzer_name = partial.get("analyzer_name", "unknown")
        analyzer_version = partial.get("analyzer_version", "0.1.0")

        engines_run.append({
            "name": analyzer_name,
            "version": analyzer_version,
        })

        # Collect findings
        for finding in partial.get("findings", []):
            all_findings.append(finding)

        # Collect IOCs
        for ioc in partial.get("iocs", []):
            all_iocs.append(ioc)

        # Collect artifacts
        for artifact in partial.get("artifacts", []):
            all_artifacts.append(artifact)

        # Collect metadata
        if "metadata" in partial:
            metadata[analyzer_name] = partial["metadata"]

    # Sort for determinism
    all_findings.sort(key=lambda f: (f.get("source", ""), f.get("id", "")))
    all_iocs.sort(key=lambda i: (i.get("type", ""), i.get("value", "")))
    all_artifacts.sort(key=lambda a: (a.get("type", ""), a.get("path", "")))
    engines_run.sort(key=lambda e: e["name"])

    # Calculate verdict and score from findings
    verdict, score = calculate_verdict(all_findings)

    # Compute config hash
    config_data = json.dumps({
        "pipeline_name": pipeline_name,
        "engines": [e["name"] for e in engines_run],
    }, sort_keys=True)
    config_hash = hashlib.sha256(config_data.encode()).hexdigest()

    # Build final report
    now = datetime.now(timezone.utc).isoformat()
    report = {
        "schema_version": "1.0.0",
        "sample_sha256": input_data["sample_sha256"],
        "tenant_id": input_data["tenant_id"],
        "file_type": input_data.get("metadata", {}).get("file_type", "unknown"),
        "hashes": metadata.get("triage-universal", {}).get("hashes", {}) or metadata.get("similarity-analyzer", {}).get("hashes", {}),
        "summary": {
            "verdict": verdict,
            "score": score,
        },
        "findings": all_findings,
        "iocs": all_iocs,
        "artifacts": all_artifacts,
        "provenance": {
            "pipeline_name": pipeline_name,
            "pipeline_hash": pipeline_hash,
            "engines": engines_run,
            "config_hash": config_hash,
            "deterministic_run": True,
        },
        "timestamps": {
            "analysis_start": input_data.get("metadata", {}).get("analysis_start", now),
            "analysis_end": now,
        },
        "_metadata": metadata,  # Internal metadata from analyzers
    }

    return report


def calculate_verdict(findings: list[dict]) -> tuple[str, int]:
    """
    Calculate verdict and score from findings.

    Args:
        findings: List of findings

    Returns:
        Tuple of (verdict, score)
    """
    if not findings:
        return "unknown", 0

    # Severity weights
    weights = {
        "CRITICAL": 100,
        "HIGH": 85,
        "MEDIUM": 65,
        "LOW": 10,
    }

    score = 0
    for finding in findings:
        severity = finding.get("severity", "LOW")
        confidence = finding.get("confidence", 50)
        weight = weights.get(severity, 0)
        score += weight * (confidence / 100)

    # Cap score at 100
    score = min(100, int(score))

    # Determine verdict
    if score >= 75:
        verdict = "malicious"
    elif score >= 50:
        verdict = "suspicious"
    elif score > 0:
        verdict = "benign"
    else:
        verdict = "unknown"

    return verdict, score


def merge_with_base_report(
    base_report: dict,
    partials: list[dict],
    pipeline_name: str,
    pipeline_hash: str,
) -> dict:
    """
    Merge partial outputs with an existing base report.

    Used when triage-universal produces a full report and other analyzers add to it.

    Args:
        base_report: Base report (from triage-universal)
        partials: List of partial outputs to merge
        pipeline_name: Pipeline name
        pipeline_hash: Pipeline hash

    Returns:
        Merged report
    """
    # Extract findings/iocs/artifacts from base report
    base_findings = base_report.get("findings", [])
    base_iocs = base_report.get("iocs", [])
    base_artifacts = base_report.get("artifacts", [])
    base_engines = base_report.get("provenance", {}).get("engines", [])

    # Merge with partials
    all_partials = []

    # Create a pseudo-partial from base report
    if base_report.get("analyzer_name"):
        all_partials.append({
            "analyzer_name": base_report.get("analyzer_name", "base"),
            "analyzer_version": base_report.get("analyzer_version", "0.1.0"),
            "findings": base_findings,
            "iocs": base_iocs,
            "artifacts": base_artifacts,
        })

    all_partials.extend(partials)

    # Use standard merge
    input_data = {
        "sample_sha256": base_report.get("sample_sha256", ""),
        "tenant_id": base_report.get("tenant_id", ""),
        "metadata": {
            "file_type": base_report.get("file_type", "unknown"),
            "analysis_start": base_report.get("timestamps", {}).get("analysis_start", ""),
        },
    }

    merged = merge_partial_outputs(all_partials, input_data, pipeline_name, pipeline_hash)

    # Preserve base report hashes if available
    if base_report.get("hashes"):
        merged["hashes"] = base_report["hashes"]

    return merged
