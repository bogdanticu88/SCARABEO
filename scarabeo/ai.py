"""AI-powered report enrichment using a local Ollama model."""

from datetime import datetime, timezone

from scarabeo.llm import OllamaClient


def generate_report_narrative(report: dict, client: OllamaClient) -> str:
    """
    Generate a 3–5 sentence executive summary of the analysis report.

    Includes verdict, score, file type, top-5 findings, and IOC count.
    """
    summary = report.get("summary", {})
    verdict = summary.get("verdict", "unknown")
    score = summary.get("score", 0)
    file_type = report.get("file_type", "unknown")
    findings = report.get("findings", [])
    ioc_count = len(report.get("iocs", []))

    # Top-5 findings by severity priority
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    top_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "LOW"), 4))[:5]
    findings_text = "\n".join(
        f"  - [{f.get('severity')}] {f.get('title')}: {f.get('description', '')[:120]}"
        for f in top_findings
    ) or "  No findings."

    prompt = (
        f"You are a malware analyst. Write a concise 3–5 sentence executive summary "
        f"of the following analysis result. Use plain English suitable for a security team briefing.\n\n"
        f"File type: {file_type}\n"
        f"Verdict: {verdict}\n"
        f"Risk score: {score}/100\n"
        f"IOC count: {ioc_count}\n"
        f"Top findings:\n{findings_text}\n\n"
        f"Summary:"
    )

    messages = [{"role": "user", "content": prompt}]
    return client.chat(messages).strip()


def explain_finding(finding: dict, client: OllamaClient) -> str:
    """
    Produce a 2–3 sentence plain-English explanation of a single finding,
    including MITRE ATT&CK context where applicable.
    """
    evidence_items = finding.get("evidence", [])
    evidence_text = "; ".join(
        f"{e.get('type')}: {e.get('value', '')[:80]}" for e in evidence_items[:3]
    ) or "none provided"

    prompt = (
        f"You are a malware analyst. Explain the following security finding in 2–3 plain English sentences. "
        f"Include any relevant MITRE ATT&CK context.\n\n"
        f"Title: {finding.get('title')}\n"
        f"Severity: {finding.get('severity')}\n"
        f"Confidence: {finding.get('confidence')}%\n"
        f"Description: {finding.get('description', '')[:300]}\n"
        f"Evidence: {evidence_text}\n\n"
        f"Explanation:"
    )

    messages = [{"role": "user", "content": prompt}]
    return client.chat(messages).strip()


def suggest_remediation(report: dict, client: OllamaClient) -> str:
    """
    Generate containment steps, detection opportunities, and indicators to
    monitor based on the full report.
    """
    summary = report.get("summary", {})
    verdict = summary.get("verdict", "unknown")
    score = summary.get("score", 0)
    findings = report.get("findings", [])
    iocs = report.get("iocs", [])

    finding_lines = "\n".join(
        f"  - [{f.get('severity')}] {f.get('title')}" for f in findings
    ) or "  None."

    top_iocs = iocs[:10]
    ioc_lines = "\n".join(
        f"  - {i.get('type')}: {i.get('value')}" for i in top_iocs
    ) or "  None."

    prompt = (
        f"You are a malware analyst. Based on the analysis below, provide:\n"
        f"1. Immediate containment steps\n"
        f"2. Detection opportunities (SIEM queries, EDR rules, network signatures)\n"
        f"3. Indicators to monitor going forward\n\n"
        f"Verdict: {verdict} (score {score}/100)\n"
        f"Findings:\n{finding_lines}\n"
        f"Top IOCs:\n{ioc_lines}\n\n"
        f"Remediation advice:"
    )

    messages = [{"role": "user", "content": prompt}]
    return client.chat(messages).strip()


def enrich_report_with_ai(report: dict, client: OllamaClient) -> dict:
    """
    Generate a narrative summary and remediation advice for the report.

    Finding-level explanations are intentionally excluded here — they are
    generated on-demand via the API to avoid unbounded latency.

    Returns:
        dict with keys: narrative, remediation, generated_at, model
    """
    narrative = generate_report_narrative(report, client)
    remediation = suggest_remediation(report, client)

    return {
        "narrative": narrative,
        "remediation": remediation,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": client.model,
    }
