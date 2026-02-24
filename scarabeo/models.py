"""Normalized internal analysis result model.

This module defines the canonical in-process representation of a single
analyzer's output. It is not a wire format — adapters in scarabeo.adapters
handle conversion to and from partial.schema.json / report.schema.json.

Six top-level sections:
  static   — file properties, hashes, entropy, extracted strings count
  iocs     — normalized indicator records
  evasion  — evasion indicators derived from findings and metadata
  metadata — analyzer identity, sample identity, timestamps
  findings — security findings with evidence
  artifacts— files produced during analysis
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH = "hash"
    MUTEX = "mutex"
    FILEPATH = "filepath"
    REGISTRY = "registry"
    USERAGENT = "useragent"


# ---------------------------------------------------------------------------
# Sub-structures
# ---------------------------------------------------------------------------

@dataclass
class EvidenceItem:
    type: str
    value: str
    offset: int | None = None
    length: int | None = None

    def to_dict(self) -> dict:
        d: dict = {"type": self.type, "value": self.value}
        if self.offset is not None:
            d["offset"] = self.offset
        if self.length is not None:
            d["length"] = self.length
        return d


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: int
    description: str
    evidence: list[EvidenceItem] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source: str = ""
    references: list[str] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": [ev.to_dict() for ev in self.evidence],
            "source": self.source,
            "created_at": self.created_at,
        }
        if self.tags:
            d["tags"] = list(self.tags)
        if self.references:
            d["references"] = list(self.references)
        return d


@dataclass
class IOCRecord:
    type: IOCType
    value: str
    normalized: str
    confidence: int
    first_seen_in: str = ""
    context: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "value": self.value,
            "normalized": self.normalized,
            "confidence": self.confidence,
            "first_seen_in": self.first_seen_in,
            "context": self.context,
            "tags": list(self.tags),
        }


@dataclass
class ArtifactRecord:
    type: str
    path: str
    produced_by: str
    sha256: str | None = None
    mime: str | None = None
    size_bytes: int | None = None
    safe_preview: str | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "type": self.type,
            "path": self.path,
            "produced_by": self.produced_by,
        }
        if self.sha256 is not None:
            d["sha256"] = self.sha256
        if self.mime is not None:
            d["mime"] = self.mime
        if self.size_bytes is not None:
            d["size_bytes"] = self.size_bytes
        if self.safe_preview is not None:
            d["safe_preview"] = self.safe_preview
        return d


# ---------------------------------------------------------------------------
# Section models
# ---------------------------------------------------------------------------

@dataclass
class StaticSection:
    """
    File-level static properties.

    Populated primarily by triage-universal and PE/ELF-specific analyzers.
    size_bytes is 0 when the adapter cannot derive it from the analyzer
    output; callers may patch it from ingest service metadata if available.
    """
    file_type: str
    size_bytes: int
    hashes: dict
    entropy: float = 0.0
    chunk_entropies: list[dict] = field(default_factory=list)
    strings_count: int = 0
    strings_artifact_path: str | None = None


@dataclass
class EvasionSection:
    """
    Evasion indicators derived from findings and analyzer metadata.

    Not emitted directly by analyzers — populated by the adapter based on
    finding tags (packing, encryption, entropy, anti-debug, anti-vm) and
    any explicit evasion metadata a specialized analyzer may include.
    """
    high_entropy_detected: bool = False
    entropy_score: float | None = None
    packing_suspected: bool = False
    obfuscation_indicators: list[str] = field(default_factory=list)
    anti_analysis_indicators: list[str] = field(default_factory=list)


@dataclass
class MetadataSection:
    """
    Analyzer identity and sample provenance.

    raw holds any analyzer-specific key/value pairs that do not map into
    the other sections, allowing pass-through without data loss.
    """
    analyzer_name: str
    analyzer_version: str
    sample_sha256: str
    tenant_id: str
    filename: str | None = None
    mime_type: str | None = None
    analysis_start: str | None = None
    analysis_end: str | None = None
    pipeline_name: str = ""
    pipeline_hash: str = ""
    raw: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Top-level model
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    """
    Normalized internal analysis result.

    Produced by scarabeo.adapters from raw analyzer output. Used as the
    canonical in-process representation before any serialization.
    """
    metadata: MetadataSection
    static: StaticSection
    iocs: list[IOCRecord]
    evasion: EvasionSection
    findings: list[Finding]
    artifacts: list[ArtifactRecord]

    def to_partial(self) -> dict:
        """
        Serialize to a partial.schema.json-conforming dict.

        The returned dict passes validate_partial() and can be fed directly
        into merge_partial_outputs(). Analyzer-specific metadata is embedded
        in the 'metadata' key, which partial.schema.json allows as a free-form
        object (additionalProperties: true).
        """
        return {
            "schema_version": "1.0.0",
            "analyzer_name": self.metadata.analyzer_name,
            "analyzer_version": self.metadata.analyzer_version,
            "findings": [f.to_dict() for f in self.findings],
            "iocs": [i.to_dict() for i in self.iocs],
            "artifacts": [a.to_dict() for a in self.artifacts],
            "metadata": {
                "hashes": self.static.hashes,
                "file_type": self.static.file_type,
                "entropy": self.static.entropy,
                "strings_count": self.static.strings_count,
                "evasion": {
                    "high_entropy_detected": self.evasion.high_entropy_detected,
                    "packing_suspected": self.evasion.packing_suspected,
                    "entropy_score": self.evasion.entropy_score,
                    "obfuscation_indicators": self.evasion.obfuscation_indicators,
                    "anti_analysis_indicators": self.evasion.anti_analysis_indicators,
                },
                **self.metadata.raw,
            },
        }
