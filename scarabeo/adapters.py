"""Adapters for mapping raw analyzer output dicts into AnalysisResult.

Three entry points:

  from_partial(data)         — partial.schema.json dict (any analyzer)
  from_triage_report(data)   — triage-universal's full report.json output
  from_report(data)          — merged report.schema.json (for re-processing)

These are additive: existing schemas, the merger, and the validator are
unchanged. Adapters sit alongside them and are used by callers that want
a typed, inspectable model rather than raw dicts.
"""

from __future__ import annotations

from scarabeo.models import (
    AnalysisResult,
    ArtifactRecord,
    EvasionSection,
    EvidenceItem,
    Finding,
    IOCRecord,
    IOCType,
    MetadataSection,
    Severity,
    StaticSection,
)

# Tags that signal evasion-related findings
_ENTROPY_TAGS = frozenset(["packing", "encryption", "entropy"])
_OBFUSCATION_TAGS = frozenset(["obfuscation"])
_ANTI_ANALYSIS_TAGS = frozenset(["anti-debug", "anti-vm", "anti-sandbox"])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _map_finding(raw: dict) -> Finding:
    return Finding(
        id=raw["id"],
        title=raw["title"],
        severity=Severity(raw["severity"]),
        confidence=int(raw["confidence"]),
        description=raw["description"],
        evidence=[
            EvidenceItem(
                type=ev["type"],
                value=ev["value"],
                offset=ev.get("offset"),
                length=ev.get("length"),
            )
            for ev in raw.get("evidence", [])
        ],
        tags=list(raw.get("tags", [])),
        source=raw.get("source", ""),
        references=list(raw.get("references", [])),
        created_at=raw.get("created_at", ""),
    )


def _map_ioc(raw: dict) -> IOCRecord:
    return IOCRecord(
        type=IOCType(raw["type"]),
        value=raw["value"],
        normalized=raw.get("normalized", raw["value"]),
        confidence=int(raw["confidence"]),
        first_seen_in=raw.get("first_seen_in", ""),
        context=raw.get("context", ""),
        tags=list(raw.get("tags", [])),
    )


def _map_artifact(raw: dict) -> ArtifactRecord:
    return ArtifactRecord(
        type=raw["type"],
        path=raw["path"],
        produced_by=raw.get("produced_by", ""),
        sha256=raw.get("sha256"),
        mime=raw.get("mime"),
        size_bytes=raw.get("size_bytes"),
        safe_preview=raw.get("safe_preview"),
    )


def _derive_evasion(findings: list[Finding], analyzer_meta: dict) -> EvasionSection:
    """
    Derive an EvasionSection from findings tags and analyzer metadata.

    Priority order:
    1. Explicit evasion block in analyzer_meta (from to_partial() round-trips)
    2. Finding tags (packing, encryption, entropy, obfuscation, anti-*)
    3. Entropy score in analyzer_meta >= HIGH_ENTROPY_THRESHOLD (7.5)
    """
    obfuscation: list[str] = []
    anti_analysis: list[str] = []
    high_entropy = False
    packing = False

    entropy_score = analyzer_meta.get("entropy")
    if isinstance(entropy_score, (int, float)) and entropy_score >= 7.5:
        high_entropy = True

    for f in findings:
        tag_set = frozenset(t.lower() for t in f.tags)
        if tag_set & _ENTROPY_TAGS:
            high_entropy = True
            packing = True
            if f.title not in obfuscation:
                obfuscation.append(f.title)
        if tag_set & _OBFUSCATION_TAGS:
            if f.title not in obfuscation:
                obfuscation.append(f.title)
        if tag_set & _ANTI_ANALYSIS_TAGS:
            if f.title not in anti_analysis:
                anti_analysis.append(f.title)

    # Absorb explicit evasion block written by to_partial()
    nested = analyzer_meta.get("evasion", {})
    if nested.get("high_entropy_detected"):
        high_entropy = True
    if nested.get("packing_suspected"):
        packing = True
    for item in nested.get("obfuscation_indicators", []):
        if item not in obfuscation:
            obfuscation.append(item)
    for item in nested.get("anti_analysis_indicators", []):
        if item not in anti_analysis:
            anti_analysis.append(item)
    if isinstance(nested.get("entropy_score"), (int, float)):
        entropy_score = nested["entropy_score"]

    return EvasionSection(
        high_entropy_detected=high_entropy,
        entropy_score=float(entropy_score) if isinstance(entropy_score, (int, float)) else None,
        packing_suspected=packing,
        obfuscation_indicators=obfuscation,
        anti_analysis_indicators=anti_analysis,
    )


# ---------------------------------------------------------------------------
# Public adapters
# ---------------------------------------------------------------------------

def from_partial(data: dict) -> AnalysisResult:
    """
    Map a partial.schema.json-conforming dict to AnalysisResult.

    The 'metadata' key is the free-form object that analyzers use to pass
    analyzer-specific state. This adapter reads hashes, entropy, and
    strings_count from it when present.
    """
    analyzer_meta = data.get("metadata") or {}
    hashes = analyzer_meta.get("hashes") or {}
    sample_sha256 = hashes.get("sha256", "")

    findings = [_map_finding(f) for f in data.get("findings", [])]
    iocs = [_map_ioc(i) for i in data.get("iocs", [])]
    artifacts = [_map_artifact(a) for a in data.get("artifacts", [])]

    # Keys consumed by dedicated sections — exclude from raw passthrough
    _consumed = {"hashes", "evasion", "entropy", "strings_count", "file_type",
                 "tenant_id", "analysis_start", "analysis_end",
                 "pipeline_name", "pipeline_hash"}

    meta = MetadataSection(
        analyzer_name=data["analyzer_name"],
        analyzer_version=data["analyzer_version"],
        sample_sha256=sample_sha256,
        tenant_id=analyzer_meta.get("tenant_id", ""),
        filename=analyzer_meta.get("filename"),
        mime_type=analyzer_meta.get("mime_type"),
        analysis_start=analyzer_meta.get("analysis_start"),
        analysis_end=analyzer_meta.get("analysis_end"),
        pipeline_name=analyzer_meta.get("pipeline_name", ""),
        pipeline_hash=analyzer_meta.get("pipeline_hash", ""),
        raw={k: v for k, v in analyzer_meta.items() if k not in _consumed},
    )

    static = StaticSection(
        file_type=analyzer_meta.get("file_type", "unknown"),
        size_bytes=int(analyzer_meta.get("size_bytes", 0)),
        hashes=hashes,
        entropy=float(analyzer_meta.get("entropy", 0.0)),
        chunk_entropies=list(analyzer_meta.get("chunk_entropies", [])),
        strings_count=int(analyzer_meta.get("strings_count", 0)),
    )

    evasion = _derive_evasion(findings, analyzer_meta)

    return AnalysisResult(
        metadata=meta,
        static=static,
        iocs=iocs,
        evasion=evasion,
        findings=findings,
        artifacts=artifacts,
    )


def from_triage_report(data: dict) -> AnalysisResult:
    """
    Map a triage-universal report dict to AnalysisResult.

    Triage-universal emits a report.schema.json-compatible structure (not a
    partial): provenance carries engine identity, and there is no top-level
    'analyzer_name' key. This adapter extracts those fields from provenance.

    The evasion section is derived from findings tags — triage-universal uses
    tags ['encryption', 'packing', 'entropy'] on high-entropy findings and
    ['network', 'ioc', 'c2'] on network findings.
    """
    provenance = data.get("provenance") or {}
    engines = provenance.get("engines") or []
    timestamps = data.get("timestamps") or {}
    hashes = data.get("hashes") or {}

    analyzer_name = engines[0]["name"] if engines else "triage-universal"
    analyzer_version = engines[0]["version"] if engines else "unknown"

    sample_sha256 = data.get("sample_sha256") or hashes.get("sha256", "")

    findings = [_map_finding(f) for f in data.get("findings", [])]
    iocs = [_map_ioc(i) for i in data.get("iocs", [])]
    artifacts_raw = data.get("artifacts") or []
    artifacts = [_map_artifact(a) for a in artifacts_raw]

    # Derive strings info from the strings artifact produced by triage-universal
    strings_count = 0
    strings_artifact_path: str | None = None
    for art in artifacts_raw:
        if art.get("type") == "strings":
            # triage-universal stores character count in size_bytes
            strings_count = int(art.get("size_bytes", 0))
            strings_artifact_path = art.get("path")
            break

    meta = MetadataSection(
        analyzer_name=analyzer_name,
        analyzer_version=analyzer_version,
        sample_sha256=sample_sha256,
        tenant_id=data.get("tenant_id", ""),
        analysis_start=timestamps.get("analysis_start"),
        analysis_end=timestamps.get("analysis_end"),
        pipeline_name=provenance.get("pipeline_name", ""),
        pipeline_hash=provenance.get("pipeline_hash", ""),
        raw=data.get("_metadata") or {},
    )

    static = StaticSection(
        file_type=data.get("file_type", "unknown"),
        size_bytes=0,  # not in triage-universal output; patch from ingest metadata
        hashes=hashes,
        strings_count=strings_count,
        strings_artifact_path=strings_artifact_path,
    )

    evasion = _derive_evasion(findings, {})

    return AnalysisResult(
        metadata=meta,
        static=static,
        iocs=iocs,
        evasion=evasion,
        findings=findings,
        artifacts=artifacts,
    )


def from_report(data: dict, *, analyzer_name: str = "merged") -> AnalysisResult:
    """
    Map a merged report.schema.json dict to AnalysisResult.

    Useful for re-inspecting or re-processing a stored report through the
    normalized model. Re-uses from_triage_report since the full report has
    the same top-level structure, then stamps the caller-supplied name.
    """
    result = from_triage_report(data)
    result.metadata.analyzer_name = analyzer_name
    result.metadata.analyzer_version = "merged"
    return result
