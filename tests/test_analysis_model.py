"""Tests for the normalized AnalysisResult model and its adapters.

Fixture strategy:
  - tests/fixtures/triage_universal_output.json  — realistic triage-universal
    report output (full report.schema.json-compatible structure).
  - tests/examples/report.json                   — merged multi-analyzer report.
  - Inline partial dicts for from_partial() tests.

No Docker, no DB, no S3 — pure unit tests.
"""

import json
from pathlib import Path

import pytest

from scarabeo.adapters import from_partial, from_report, from_triage_report
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
from scarabeo.validation import validate_partial

FIXTURES_DIR = Path(__file__).parent / "fixtures"
EXAMPLES_DIR = Path(__file__).parent / "examples"

SHA256 = "a" * 64
PIPELINE_HASH = "b" * 64


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def triage_output() -> dict:
    """Load the triage-universal output fixture."""
    with open(FIXTURES_DIR / "triage_universal_output.json") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def merged_report() -> dict:
    """Load the merged report example."""
    with open(EXAMPLES_DIR / "report.json") as f:
        return json.load(f)


def _minimal_partial(analyzer_name: str = "test-analyzer") -> dict:
    """Return a minimal valid partial dict."""
    return {
        "schema_version": "1.0.0",
        "analyzer_name": analyzer_name,
        "analyzer_version": "1.0.0",
        "findings": [],
        "iocs": [],
        "artifacts": [],
    }


def _partial_with_findings() -> dict:
    return {
        "schema_version": "1.0.0",
        "analyzer_name": "pe-analyzer",
        "analyzer_version": "0.2.0",
        "findings": [
            {
                "id": "f-001",
                "title": "Anti-debug Routine",
                "severity": "HIGH",
                "confidence": 85,
                "description": "IsDebuggerPresent call detected",
                "evidence": [{"type": "import", "value": "IsDebuggerPresent", "offset": 512}],
                "tags": ["anti-debug", "evasion"],
                "source": "pe-analyzer",
                "references": ["https://attack.mitre.org/techniques/T1622/"],
                "created_at": "2024-06-01T12:00:00+00:00",
            },
            {
                "id": "f-002",
                "title": "Packed Section Detected",
                "severity": "MEDIUM",
                "confidence": 70,
                "description": "UPX packed section found",
                "evidence": [{"type": "section", "value": "UPX0"}],
                "tags": ["packing", "encryption"],
                "source": "pe-analyzer",
                "created_at": "2024-06-01T12:00:00+00:00",
            },
        ],
        "iocs": [
            {
                "type": "ip",
                "value": "192.168.1.100",
                "normalized": "192.168.1.100",
                "confidence": 75,
                "first_seen_in": SHA256,
                "context": "Hardcoded C2",
                "tags": ["c2"],
            }
        ],
        "artifacts": [
            {
                "type": "pe-header",
                "path": "artifacts/pe_header.bin",
                "sha256": "c" * 64,
                "produced_by": "pe-analyzer",
                "size_bytes": 512,
            }
        ],
        "metadata": {
            "hashes": {"sha256": SHA256, "md5": "d" * 32},
            "file_type": "PE32",
            "entropy": 6.2,
            "strings_count": 382,
        },
    }


# ---------------------------------------------------------------------------
# TestModels — dataclass instantiation and serialization
# ---------------------------------------------------------------------------

class TestModels:

    def test_severity_enum_values(self):
        assert Severity.LOW.value == "LOW"
        assert Severity.CRITICAL.value == "CRITICAL"

    def test_ioc_type_enum_values(self):
        assert IOCType.IP.value == "ip"
        assert IOCType.USERAGENT.value == "useragent"

    def test_evidence_item_to_dict_optional_fields_omitted(self):
        ev = EvidenceItem(type="import", value="VirtualAlloc")
        d = ev.to_dict()
        assert d == {"type": "import", "value": "VirtualAlloc"}
        assert "offset" not in d
        assert "length" not in d

    def test_evidence_item_to_dict_with_offset(self):
        ev = EvidenceItem(type="bytes", value="4d5a", offset=0, length=2)
        d = ev.to_dict()
        assert d["offset"] == 0
        assert d["length"] == 2

    def test_finding_to_dict_minimal(self):
        f = Finding(
            id="f1", title="Test", severity=Severity.LOW,
            confidence=50, description="desc",
            evidence=[EvidenceItem("string", "test")],
            source="test", created_at="2024-01-01T00:00:00Z",
        )
        d = f.to_dict()
        assert d["severity"] == "LOW"
        assert d["evidence"] == [{"type": "string", "value": "test"}]
        assert "tags" not in d          # empty list not serialized
        assert "references" not in d

    def test_finding_to_dict_includes_tags_when_set(self):
        f = Finding(
            id="f1", title="T", severity=Severity.HIGH,
            confidence=80, description="d",
            evidence=[EvidenceItem("t", "v")],
            tags=["c2", "evasion"], source="s", created_at="2024-01-01T00:00:00Z",
        )
        d = f.to_dict()
        assert d["tags"] == ["c2", "evasion"]

    def test_ioc_record_to_dict(self):
        ioc = IOCRecord(
            type=IOCType.DOMAIN, value="evil.com",
            normalized="evil.com", confidence=90,
            first_seen_in=SHA256, context="C2", tags=["c2"],
        )
        d = ioc.to_dict()
        assert d["type"] == "domain"
        assert d["normalized"] == "evil.com"

    def test_artifact_record_to_dict_omits_none_fields(self):
        art = ArtifactRecord(type="strings", path="/artifacts/strings.txt", produced_by="triage-universal")
        d = art.to_dict()
        assert "sha256" not in d
        assert "mime" not in d
        assert "size_bytes" not in d

    def test_artifact_record_to_dict_with_all_fields(self):
        art = ArtifactRecord(
            type="pe-header", path="/artifacts/hdr.bin",
            produced_by="pe-analyzer", sha256="e" * 64,
            mime="application/octet-stream", size_bytes=512,
        )
        d = art.to_dict()
        assert d["sha256"] == "e" * 64
        assert d["size_bytes"] == 512

    def test_analysis_result_sections_accessible(self):
        result = AnalysisResult(
            metadata=MetadataSection(
                analyzer_name="test", analyzer_version="1.0",
                sample_sha256=SHA256, tenant_id="t1",
            ),
            static=StaticSection(file_type="PE32", size_bytes=0, hashes={"sha256": SHA256}),
            iocs=[],
            evasion=EvasionSection(),
            findings=[],
            artifacts=[],
        )
        assert result.metadata.analyzer_name == "test"
        assert result.static.file_type == "PE32"
        assert result.evasion.high_entropy_detected is False
        assert result.findings == []
        assert result.iocs == []
        assert result.artifacts == []


# ---------------------------------------------------------------------------
# TestFromTriageReport — primary adapter for triage-universal fixture
# ---------------------------------------------------------------------------

class TestFromTriageReport:

    def test_returns_analysis_result(self, triage_output):
        result = from_triage_report(triage_output)
        assert isinstance(result, AnalysisResult)

    def test_metadata_analyzer_name(self, triage_output):
        result = from_triage_report(triage_output)
        assert result.metadata.analyzer_name == "triage-universal"

    def test_metadata_analyzer_version(self, triage_output):
        result = from_triage_report(triage_output)
        assert result.metadata.analyzer_version == "0.1.0"

    def test_metadata_sample_sha256(self, triage_output):
        result = from_triage_report(triage_output)
        assert result.metadata.sample_sha256 == "a" * 64

    def test_metadata_tenant_id(self, triage_output):
        result = from_triage_report(triage_output)
        assert result.metadata.tenant_id == "tenant-test"

    def test_metadata_timestamps(self, triage_output):
        result = from_triage_report(triage_output)
        assert result.metadata.analysis_start == "2024-06-01T12:00:00+00:00"
        assert result.metadata.analysis_end == "2024-06-01T12:00:02+00:00"

    def test_metadata_pipeline(self, triage_output):
        result = from_triage_report(triage_output)
        assert result.metadata.pipeline_name == "triage"

    def test_static_file_type(self, triage_output):
        result = from_triage_report(triage_output)
        assert result.static.file_type == "unknown"

    def test_static_hashes_populated(self, triage_output):
        result = from_triage_report(triage_output)
        assert result.static.hashes["sha256"] == "a" * 64
        assert "md5" in result.static.hashes
        assert "sha1" in result.static.hashes

    def test_static_strings_count_from_artifact(self, triage_output):
        result = from_triage_report(triage_output)
        # triage-universal sets size_bytes to char count in strings artifact
        assert result.static.strings_count == 1420

    def test_static_strings_artifact_path(self, triage_output):
        result = from_triage_report(triage_output)
        assert result.static.strings_artifact_path == "artifacts/strings.txt"

    def test_findings_count(self, triage_output):
        result = from_triage_report(triage_output)
        assert len(result.findings) == 3

    def test_findings_severity_enum(self, triage_output):
        result = from_triage_report(triage_output)
        severities = {f.severity for f in result.findings}
        assert Severity.MEDIUM in severities
        assert Severity.HIGH in severities
        assert Severity.LOW in severities

    def test_findings_evidence_mapped(self, triage_output):
        result = from_triage_report(triage_output)
        entropy_finding = next(f for f in result.findings if "Entropy" in f.title)
        assert len(entropy_finding.evidence) == 3
        assert all(isinstance(ev, EvidenceItem) for ev in entropy_finding.evidence)

    def test_iocs_count(self, triage_output):
        result = from_triage_report(triage_output)
        assert len(result.iocs) == 7

    def test_iocs_types_correct(self, triage_output):
        result = from_triage_report(triage_output)
        types = {ioc.type for ioc in result.iocs}
        assert IOCType.URL in types
        assert IOCType.DOMAIN in types
        assert IOCType.IP in types
        assert IOCType.EMAIL in types

    def test_ioc_normalized_field(self, triage_output):
        result = from_triage_report(triage_output)
        email_ioc = next(i for i in result.iocs if i.type == IOCType.EMAIL)
        assert email_ioc.normalized == "operator@attacker.org"

    def test_artifacts_count(self, triage_output):
        result = from_triage_report(triage_output)
        assert len(result.artifacts) == 1

    def test_artifact_fields(self, triage_output):
        result = from_triage_report(triage_output)
        art = result.artifacts[0]
        assert art.type == "strings"
        assert art.produced_by == "triage-universal"
        assert art.sha256 == "b" * 64
        assert art.size_bytes == 1420

    # Evasion section — derived from entropy and network findings
    def test_evasion_high_entropy_detected(self, triage_output):
        result = from_triage_report(triage_output)
        assert result.evasion.high_entropy_detected is True

    def test_evasion_packing_suspected(self, triage_output):
        result = from_triage_report(triage_output)
        assert result.evasion.packing_suspected is True

    def test_evasion_obfuscation_indicators_populated(self, triage_output):
        result = from_triage_report(triage_output)
        assert len(result.evasion.obfuscation_indicators) > 0
        assert "High Entropy Content Detected" in result.evasion.obfuscation_indicators

    def test_evasion_anti_analysis_empty_for_triage(self, triage_output):
        # Triage-universal does not emit anti-debug/anti-vm tags
        result = from_triage_report(triage_output)
        assert result.evasion.anti_analysis_indicators == []


# ---------------------------------------------------------------------------
# TestFromPartial — partial.schema.json adapter
# ---------------------------------------------------------------------------

class TestFromPartial:

    def test_minimal_partial_returns_result(self):
        result = from_partial(_minimal_partial())
        assert isinstance(result, AnalysisResult)

    def test_analyzer_name_preserved(self):
        result = from_partial(_minimal_partial("elf-analyzer"))
        assert result.metadata.analyzer_name == "elf-analyzer"

    def test_empty_sections(self):
        result = from_partial(_minimal_partial())
        assert result.findings == []
        assert result.iocs == []
        assert result.artifacts == []

    def test_findings_mapped_correctly(self):
        result = from_partial(_partial_with_findings())
        assert len(result.findings) == 2
        anti_debug = next(f for f in result.findings if "Anti-debug" in f.title)
        assert anti_debug.severity == Severity.HIGH
        assert anti_debug.confidence == 85
        assert anti_debug.evidence[0].offset == 512

    def test_ioc_mapped_correctly(self):
        result = from_partial(_partial_with_findings())
        assert len(result.iocs) == 1
        ioc = result.iocs[0]
        assert ioc.type == IOCType.IP
        assert ioc.value == "192.168.1.100"
        assert ioc.confidence == 75

    def test_artifact_mapped_correctly(self):
        result = from_partial(_partial_with_findings())
        art = result.artifacts[0]
        assert art.type == "pe-header"
        assert art.sha256 == "c" * 64

    def test_static_hashes_from_metadata(self):
        result = from_partial(_partial_with_findings())
        assert result.static.hashes["sha256"] == SHA256
        assert result.static.hashes["md5"] == "d" * 32

    def test_static_entropy_from_metadata(self):
        result = from_partial(_partial_with_findings())
        assert result.static.entropy == pytest.approx(6.2)

    def test_static_strings_count_from_metadata(self):
        result = from_partial(_partial_with_findings())
        assert result.static.strings_count == 382

    def test_evasion_from_anti_debug_tags(self):
        result = from_partial(_partial_with_findings())
        assert result.evasion.anti_analysis_indicators == ["Anti-debug Routine"]

    def test_evasion_from_packing_tags(self):
        result = from_partial(_partial_with_findings())
        assert result.evasion.packing_suspected is True
        assert result.evasion.high_entropy_detected is True

    def test_partial_without_metadata_key(self):
        data = _minimal_partial()
        # No 'metadata' key at all — should not raise
        result = from_partial(data)
        assert result.static.hashes == {}
        assert result.static.entropy == 0.0


# ---------------------------------------------------------------------------
# TestFromReport — merged report adapter
# ---------------------------------------------------------------------------

class TestFromReport:

    def test_returns_analysis_result(self, merged_report):
        result = from_report(merged_report)
        assert isinstance(result, AnalysisResult)

    def test_default_analyzer_name_is_merged(self, merged_report):
        result = from_report(merged_report)
        assert result.metadata.analyzer_name == "merged"

    def test_custom_analyzer_name(self, merged_report):
        result = from_report(merged_report, analyzer_name="post-processor")
        assert result.metadata.analyzer_name == "post-processor"

    def test_findings_from_merged_report(self, merged_report):
        result = from_report(merged_report)
        assert len(result.findings) == len(merged_report["findings"])

    def test_iocs_from_merged_report(self, merged_report):
        result = from_report(merged_report)
        assert len(result.iocs) == len(merged_report["iocs"])

    def test_hashes_preserved(self, merged_report):
        result = from_report(merged_report)
        assert result.static.hashes == merged_report["hashes"]

    def test_tenant_id_preserved(self, merged_report):
        result = from_report(merged_report)
        assert result.metadata.tenant_id == merged_report["tenant_id"]


# ---------------------------------------------------------------------------
# TestToPartialRoundTrip — to_partial() must pass validate_partial()
# ---------------------------------------------------------------------------

class TestToPartialRoundTrip:

    def test_triage_output_round_trips(self, triage_output):
        result = from_triage_report(triage_output)
        partial = result.to_partial()
        # Must not raise
        validate_partial(partial, result.metadata.analyzer_name)

    def test_partial_with_findings_round_trips(self):
        result = from_partial(_partial_with_findings())
        partial = result.to_partial()
        validate_partial(partial, result.metadata.analyzer_name)

    def test_minimal_partial_round_trips(self):
        result = from_partial(_minimal_partial())
        partial = result.to_partial()
        validate_partial(partial, result.metadata.analyzer_name)

    def test_to_partial_schema_version(self, triage_output):
        partial = from_triage_report(triage_output).to_partial()
        assert partial["schema_version"] == "1.0.0"

    def test_to_partial_analyzer_name(self, triage_output):
        result = from_triage_report(triage_output)
        partial = result.to_partial()
        assert partial["analyzer_name"] == "triage-universal"

    def test_to_partial_metadata_contains_evasion(self, triage_output):
        result = from_triage_report(triage_output)
        partial = result.to_partial()
        evasion = partial["metadata"]["evasion"]
        assert evasion["high_entropy_detected"] is True
        assert evasion["packing_suspected"] is True

    def test_to_partial_metadata_contains_hashes(self, triage_output):
        result = from_triage_report(triage_output)
        partial = result.to_partial()
        assert partial["metadata"]["hashes"]["sha256"] == "a" * 64

    def test_to_partial_findings_severity_is_string(self, triage_output):
        result = from_triage_report(triage_output)
        partial = result.to_partial()
        for finding in partial["findings"]:
            assert isinstance(finding["severity"], str)

    def test_to_partial_ioc_type_is_string(self, triage_output):
        result = from_triage_report(triage_output)
        partial = result.to_partial()
        for ioc in partial["iocs"]:
            assert isinstance(ioc["type"], str)


# ---------------------------------------------------------------------------
# TestEvasionDerivation — edge cases for _derive_evasion
# ---------------------------------------------------------------------------

class TestEvasionDerivation:

    def test_no_findings_no_evasion(self):
        result = from_partial(_minimal_partial())
        assert result.evasion.high_entropy_detected is False
        assert result.evasion.packing_suspected is False
        assert result.evasion.obfuscation_indicators == []
        assert result.evasion.anti_analysis_indicators == []

    def test_entropy_in_metadata_sets_high_entropy(self):
        data = {**_minimal_partial(), "metadata": {"entropy": 7.9}}
        result = from_partial(data)
        assert result.evasion.high_entropy_detected is True
        assert result.evasion.entropy_score == pytest.approx(7.9)

    def test_entropy_below_threshold_does_not_set_high_entropy(self):
        data = {**_minimal_partial(), "metadata": {"entropy": 5.0}}
        result = from_partial(data)
        assert result.evasion.high_entropy_detected is False

    def test_anti_vm_tag_populates_anti_analysis(self):
        partial = _minimal_partial()
        partial["findings"] = [
            {
                "id": "f1",
                "title": "VM Detection",
                "severity": "MEDIUM",
                "confidence": 70,
                "description": "CPUID check",
                "evidence": [{"type": "instruction", "value": "CPUID"}],
                "tags": ["anti-vm"],
                "source": "pe-analyzer",
                "created_at": "2024-01-01T00:00:00Z",
            }
        ]
        result = from_partial(partial)
        assert "VM Detection" in result.evasion.anti_analysis_indicators

    def test_explicit_evasion_block_absorbed_on_round_trip(self, triage_output):
        # to_partial() embeds evasion; from_partial() must re-derive it correctly
        result1 = from_triage_report(triage_output)
        partial = result1.to_partial()
        result2 = from_partial(partial)
        assert result2.evasion.high_entropy_detected == result1.evasion.high_entropy_detected
        assert result2.evasion.packing_suspected == result1.evasion.packing_suspected

    def test_deduplication_of_indicators(self):
        # Two findings with same title and overlapping evasion tags
        partial = _minimal_partial()
        partial["findings"] = [
            {
                "id": "f1", "title": "Packed", "severity": "MEDIUM",
                "confidence": 70, "description": "d",
                "evidence": [{"type": "t", "value": "v"}],
                "tags": ["packing"], "source": "s",
                "created_at": "2024-01-01T00:00:00Z",
            },
            {
                "id": "f2", "title": "Packed", "severity": "HIGH",
                "confidence": 80, "description": "d2",
                "evidence": [{"type": "t", "value": "v2"}],
                "tags": ["encryption"], "source": "s",
                "created_at": "2024-01-01T00:00:00Z",
            },
        ]
        result = from_partial(partial)
        # "Packed" should appear only once despite two findings with that title
        assert result.evasion.obfuscation_indicators.count("Packed") == 1
