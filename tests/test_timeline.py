"""
Unit tests for scarabeo/timeline.py — deterministic execution timeline.

Tests cover:
- Phase ordering and stability (the primary acceptance criterion)
- Rules-based step generation from findings, IOCs, and artifacts
- Evidence reference format and completeness
- Optional AI narrative rewrite (provider mocked, invariants verified)
"""

import copy
import json
import random
from unittest.mock import MagicMock

import pytest

from scarabeo.timeline import (
    Phase,
    Timeline,
    TimelineBuilder,
    TimelineStep,
    _build_rewrite_prompt,
    rewrite_timeline_with_ai,
)


# ---------------------------------------------------------------------------
# Fixtures / builders
# ---------------------------------------------------------------------------

SHA256 = "a" * 64
PIPELINE_HASH = "b" * 64
CONFIG_HASH = "c" * 64


def _finding(
    fid: str,
    title: str,
    severity: str = "HIGH",
    confidence: int = 80,
    description: str = "",
    tags: list[str] | None = None,
    evidence: list[dict] | None = None,
) -> dict:
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "description": description or title,
        "tags": tags or [],
        "evidence": evidence or [],
        "source": "pe-analyzer",
        "created_at": "2024-01-15T10:00:00Z",
    }


def _ioc(type_: str, value: str, confidence: int = 80) -> dict:
    return {
        "type": type_,
        "value": value,
        "normalized": value,
        "confidence": confidence,
        "first_seen_in": "pe-analyzer",
    }


def _artifact(type_: str, path: str) -> dict:
    return {
        "type": type_,
        "path": path,
        "sha256": SHA256,
        "produced_by": "pe-analyzer",
    }


def _report(
    file_type: str = "PE32 executable",
    findings: list[dict] | None = None,
    iocs: list[dict] | None = None,
    artifacts: list[dict] | None = None,
) -> dict:
    return {
        "schema_version": "1.0.0",
        "sample_sha256": SHA256,
        "tenant_id": "tenant-123",
        "file_type": file_type,
        "hashes": {"sha256": SHA256},
        "summary": {"verdict": "malicious", "score": 88},
        "findings": findings or [],
        "iocs": iocs or [],
        "artifacts": artifacts or [],
        "provenance": {
            "pipeline_name": "standard",
            "pipeline_hash": PIPELINE_HASH,
            "engines": [{"name": "pe-analyzer", "version": "0.1.0"}],
            "config_hash": CONFIG_HASH,
            "deterministic_run": True,
        },
        "timestamps": {
            "analysis_start": "2024-01-15T10:00:00Z",
            "analysis_end": "2024-01-15T10:05:00Z",
        },
    }


def _full_pe_report() -> dict:
    """Report with findings spanning most execution phases."""
    return _report(
        file_type="PE32 executable",
        findings=[
            _finding("f-001", "IsDebuggerPresent anti-debug check", confidence=90),
            _finding("f-002", "VirtualAllocEx process injection API", confidence=85),
            _finding("f-003", "WriteProcessMemory process injection API", confidence=85),
            _finding("f-004", "CreateRemoteThread process injection API", confidence=85),
            _finding("f-005", "Registry persistence via Run key", confidence=78),
            _finding("f-006", "High entropy .text section — packed binary", confidence=72),
            _finding("f-007", "CreateProcess spawning child process", confidence=80),
            _finding("f-008", "InternetOpen HTTP communication", confidence=88),
        ],
        iocs=[
            _ioc("ip",     "192.0.2.1"),
            _ioc("domain", "evil.example.com"),
            _ioc("registry", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost"),
        ],
    )


def _provider_with_response(response: dict) -> MagicMock:
    """Return a mock provider whose complete() returns *response* as JSON."""
    p = MagicMock()
    p.complete = MagicMock(return_value=json.dumps(response))
    return p


builder = TimelineBuilder()


# ---------------------------------------------------------------------------
# TestPhaseOrdering
# ---------------------------------------------------------------------------

class TestPhaseOrdering:
    """Steps must always be sorted ascending by Phase value."""

    def test_steps_sorted_by_phase_enum(self):
        timeline = builder.build(_full_pe_report())
        phases = [s.phase for s in timeline.steps]
        assert phases == sorted(phases)

    def test_phase_values_are_monotonically_increasing(self):
        timeline = builder.build(_full_pe_report())
        for i in range(len(timeline.steps) - 1):
            assert timeline.steps[i].phase < timeline.steps[i + 1].phase

    def test_anti_analysis_before_c2(self):
        timeline = builder.build(_full_pe_report())
        phases = [s.phase for s in timeline.steps]
        assert Phase.ANTI_ANALYSIS in phases
        assert Phase.C2_COMMUNICATION in phases
        assert phases.index(Phase.ANTI_ANALYSIS) < phases.index(Phase.C2_COMMUNICATION)

    def test_unpacking_before_injection(self):
        report = _report(findings=[
            _finding("f-001", "High entropy packed binary — virtualalloc unpack"),
            _finding("f-002", "VirtualAllocEx process injection API"),
        ])
        timeline = builder.build(report)
        phases = [s.phase for s in timeline.steps]
        assert Phase.UNPACKING in phases
        assert Phase.PROCESS_INJECTION in phases
        assert phases.index(Phase.UNPACKING) < phases.index(Phase.PROCESS_INJECTION)

    def test_injection_before_persistence(self):
        report = _report(findings=[
            _finding("f-001", "VirtualAllocEx process injection API"),
            _finding("f-002", "Registry persistence via Run key"),
        ])
        timeline = builder.build(report)
        phases = [s.phase for s in timeline.steps]
        assert phases.index(Phase.PROCESS_INJECTION) < phases.index(Phase.PERSISTENCE)

    def test_persistence_before_c2(self):
        report = _report(
            findings=[_finding("f-001", "Registry persistence autorun key")],
            iocs=[_ioc("ip", "192.0.2.1")],
        )
        timeline = builder.build(report)
        phases = [s.phase for s in timeline.steps]
        assert phases.index(Phase.PERSISTENCE) < phases.index(Phase.C2_COMMUNICATION)

    def test_initial_load_always_first_for_pe(self):
        timeline = builder.build(_full_pe_report())
        assert timeline.steps[0].phase == Phase.INITIAL_LOAD


# ---------------------------------------------------------------------------
# TestOrderingStability
# ---------------------------------------------------------------------------

class TestOrderingStability:
    """Identical evidence must always produce identical ordering."""

    def test_same_report_same_order_on_repeated_calls(self):
        report = _full_pe_report()
        t1 = builder.build(report)
        t2 = builder.build(report)
        assert [s.phase for s in t1.steps] == [s.phase for s in t2.steps]

    def test_shuffled_findings_same_phase_order(self):
        """Shuffling the findings list must not change which phases appear."""
        report = _full_pe_report()

        shuffled = copy.deepcopy(report)
        random.shuffle(shuffled["findings"])

        t_original = builder.build(report)
        t_shuffled = builder.build(shuffled)

        assert [s.phase for s in t_original.steps] == [s.phase for s in t_shuffled.steps]

    def test_shuffled_iocs_same_phase_order(self):
        report = _full_pe_report()

        shuffled = copy.deepcopy(report)
        random.shuffle(shuffled["iocs"])

        t1 = builder.build(report)
        t2 = builder.build(shuffled)

        assert [s.phase for s in t1.steps] == [s.phase for s in t2.steps]

    def test_phase_labels_match_phase_values(self):
        timeline = builder.build(_full_pe_report())
        from scarabeo.timeline import PHASE_LABELS
        for step in timeline.steps:
            assert step.phase_label == PHASE_LABELS[step.phase]


# ---------------------------------------------------------------------------
# TestRuleMatching
# ---------------------------------------------------------------------------

class TestRuleMatching:

    def test_pe_always_generates_initial_load(self):
        """PE file with no findings still gets an INITIAL_LOAD step."""
        timeline = builder.build(_report(file_type="PE32 executable", findings=[]))
        phases = [s.phase for s in timeline.steps]
        assert Phase.INITIAL_LOAD in phases

    def test_virtualallocex_triggers_injection_step(self):
        report = _report(findings=[_finding("f-001", "VirtualAllocEx process injection API")])
        timeline = builder.build(report)
        assert any(s.phase == Phase.PROCESS_INJECTION for s in timeline.steps)

    def test_isdebuggerpresent_triggers_anti_analysis(self):
        report = _report(findings=[_finding("f-001", "IsDebuggerPresent anti-debug")])
        timeline = builder.build(report)
        assert any(s.phase == Phase.ANTI_ANALYSIS for s in timeline.steps)

    def test_network_ip_ioc_triggers_c2(self):
        report = _report(iocs=[_ioc("ip", "10.0.0.1")])
        timeline = builder.build(report)
        assert any(s.phase == Phase.C2_COMMUNICATION for s in timeline.steps)

    def test_network_domain_ioc_triggers_c2(self):
        report = _report(iocs=[_ioc("domain", "evil.example.com")])
        timeline = builder.build(report)
        assert any(s.phase == Phase.C2_COMMUNICATION for s in timeline.steps)

    def test_registry_ioc_triggers_persistence(self):
        report = _report(iocs=[_ioc("registry", "HKCU\\...\\Run\\malware")])
        timeline = builder.build(report)
        assert any(s.phase == Phase.PERSISTENCE for s in timeline.steps)

    def test_persistence_finding_triggers_persistence(self):
        report = _report(findings=[_finding("f-001", "Registry persistence via Run key")])
        timeline = builder.build(report)
        assert any(s.phase == Phase.PERSISTENCE for s in timeline.steps)

    def test_high_entropy_triggers_unpacking(self):
        report = _report(findings=[_finding("f-001", "High entropy packed section")])
        timeline = builder.build(report)
        assert any(s.phase == Phase.UNPACKING for s in timeline.steps)

    def test_shellcode_artifact_triggers_payload(self):
        report = _report(artifacts=[_artifact("shellcode", "/tmp/shell.bin")])
        timeline = builder.build(report)
        assert any(s.phase == Phase.PAYLOAD_EXECUTION for s in timeline.steps)

    def test_empty_report_produces_only_pe_initial_load(self):
        """Empty findings + empty IOCs for PE → only INITIAL_LOAD."""
        timeline = builder.build(_report(file_type="PE32 executable"))
        assert len(timeline.steps) == 1
        assert timeline.steps[0].phase == Phase.INITIAL_LOAD

    def test_non_pe_empty_report_produces_no_steps(self):
        timeline = builder.build(_report(file_type="text/plain", findings=[]))
        assert timeline.is_empty()

    def test_generated_by_is_rules(self):
        timeline = builder.build(_full_pe_report())
        assert timeline.generated_by == "rules"

    def test_c2_step_description_mentions_ioc_values(self):
        report = _report(iocs=[_ioc("ip", "192.0.2.99")])
        timeline = builder.build(report)
        c2 = next(s for s in timeline.steps if s.phase == Phase.C2_COMMUNICATION)
        assert "192.0.2.99" in c2.description


# ---------------------------------------------------------------------------
# TestEvidenceRefs
# ---------------------------------------------------------------------------

class TestEvidenceRefs:
    """Every step must carry at least one evidence reference."""

    def test_every_step_has_at_least_one_ref(self):
        timeline = builder.build(_full_pe_report())
        for step in timeline.steps:
            assert len(step.evidence_refs) >= 1, (
                f"Step {step.phase_label!r} has no evidence_refs"
            )

    def test_finding_refs_use_correct_format(self):
        """Finding refs must be 'finding:{non-empty-id}'."""
        timeline = builder.build(_full_pe_report())
        for step in timeline.steps:
            for ref in step.evidence_refs:
                if ref.startswith("finding:"):
                    fid = ref[len("finding:"):]
                    assert len(fid) > 0, f"Empty id in ref: {ref}"

    def test_ioc_refs_use_correct_format(self):
        """IOC refs must be 'ioc:{type}:{value}'."""
        report = _report(iocs=[_ioc("ip", "1.2.3.4")])
        timeline = builder.build(report)
        all_refs = [ref for step in timeline.steps for ref in step.evidence_refs]
        ioc_refs = [r for r in all_refs if r.startswith("ioc:")]
        assert any(r == "ioc:ip:1.2.3.4" for r in ioc_refs)

    def test_finding_refs_reference_real_finding_ids(self):
        """Every 'finding:X' ref must correspond to a finding in the report."""
        report = _full_pe_report()
        real_ids = {f["id"] for f in report["findings"]}
        timeline = builder.build(report)

        for step in timeline.steps:
            for ref in step.evidence_refs:
                if ref.startswith("finding:"):
                    fid = ref[len("finding:"):]
                    assert fid in real_ids, f"Dangling ref: {ref}"

    def test_confidence_within_valid_range(self):
        timeline = builder.build(_full_pe_report())
        for step in timeline.steps:
            assert 0 <= step.confidence <= 100, (
                f"Step {step.phase_label!r} has confidence {step.confidence}"
            )

    def test_ioc_refs_in_c2_step(self):
        report = _report(iocs=[_ioc("ip", "192.0.2.1"), _ioc("domain", "evil.example.com")])
        timeline = builder.build(report)
        c2 = next(s for s in timeline.steps if s.phase == Phase.C2_COMMUNICATION)
        ioc_refs = [r for r in c2.evidence_refs if r.startswith("ioc:")]
        assert len(ioc_refs) == 2

    def test_registry_ioc_ref_in_persistence_step(self):
        report = _report(iocs=[_ioc("registry", "HKCU\\...\\Run\\evil")])
        timeline = builder.build(report)
        persist = next(s for s in timeline.steps if s.phase == Phase.PERSISTENCE)
        assert any(r.startswith("ioc:registry:") for r in persist.evidence_refs)


# ---------------------------------------------------------------------------
# TestAIRewrite
# ---------------------------------------------------------------------------

class TestAIRewrite:

    def _timeline_with_steps(self, n: int = 3) -> Timeline:
        """Build a timeline that has exactly *n* steps."""
        # Use findings that trigger specific phases
        finding_titles = [
            ("f-001", "IsDebuggerPresent anti-debug check"),
            ("f-002", "VirtualAllocEx process injection"),
            ("f-003", "Registry persistence via Run key"),
            ("f-004", "InternetOpen HTTP beacon"),
            ("f-005", "High entropy packed binary"),
        ]
        findings = [_finding(fid, title) for fid, title in finding_titles[:n]]
        report = _report(
            file_type="PE32 executable",
            findings=findings,
        )
        return builder.build(report)

    def test_ai_rewrite_preserves_step_count(self):
        timeline = self._timeline_with_steps(3)
        n = len(timeline.steps)
        provider = _provider_with_response({"narratives": [f"Narrative {i}" for i in range(n)]})
        result = rewrite_timeline_with_ai(timeline, provider)
        assert len(result.steps) == n

    def test_ai_rewrite_preserves_phase_ordering(self):
        timeline = self._timeline_with_steps(3)
        n = len(timeline.steps)
        provider = _provider_with_response({"narratives": [f"Narrative {i}" for i in range(n)]})
        result = rewrite_timeline_with_ai(timeline, provider)
        phases = [s.phase for s in result.steps]
        assert phases == sorted(phases)

    def test_ai_rewrite_preserves_evidence_refs(self):
        timeline = self._timeline_with_steps(3)
        original_refs = [list(s.evidence_refs) for s in timeline.steps]
        n = len(timeline.steps)
        provider = _provider_with_response({"narratives": [f"Narrative {i}" for i in range(n)]})
        result = rewrite_timeline_with_ai(timeline, provider)
        for orig_refs, new_step in zip(original_refs, result.steps):
            assert new_step.evidence_refs == orig_refs

    def test_ai_rewrite_preserves_confidence(self):
        timeline = self._timeline_with_steps(3)
        original_confidences = [s.confidence for s in timeline.steps]
        n = len(timeline.steps)
        provider = _provider_with_response({"narratives": [f"Narrative {i}" for i in range(n)]})
        result = rewrite_timeline_with_ai(timeline, provider)
        assert [s.confidence for s in result.steps] == original_confidences

    def test_ai_rewrite_updates_descriptions(self):
        timeline = self._timeline_with_steps(2)
        n = len(timeline.steps)
        narratives = [f"AI narrative for step {i}" for i in range(n)]
        provider = _provider_with_response({"narratives": narratives})
        result = rewrite_timeline_with_ai(timeline, provider)
        for step, expected in zip(result.steps, narratives):
            assert step.description == expected

    def test_ai_rewrite_sets_generated_by(self):
        timeline = self._timeline_with_steps(2)
        n = len(timeline.steps)
        provider = _provider_with_response({"narratives": [f"n{i}" for i in range(n)]})
        result = rewrite_timeline_with_ai(timeline, provider)
        assert result.generated_by == "rules+ai"

    def test_ai_provider_error_returns_original(self):
        timeline = self._timeline_with_steps(2)
        provider = MagicMock()
        provider.complete = MagicMock(side_effect=Exception("connection refused"))
        result = rewrite_timeline_with_ai(timeline, provider)
        # Must return original unchanged
        assert result.generated_by == "rules"
        assert [s.phase for s in result.steps] == [s.phase for s in timeline.steps]

    def test_ai_wrong_narrative_count_returns_original(self):
        timeline = self._timeline_with_steps(3)
        n = len(timeline.steps)
        # Provide wrong number of narratives
        provider = _provider_with_response({"narratives": ["only one"]})
        result = rewrite_timeline_with_ai(timeline, provider)
        assert result.generated_by == "rules"
        assert len(result.steps) == n

    def test_ai_invalid_json_returns_original(self):
        timeline = self._timeline_with_steps(2)
        provider = MagicMock()
        provider.complete = MagicMock(return_value="I cannot provide JSON right now.")
        result = rewrite_timeline_with_ai(timeline, provider)
        assert result.generated_by == "rules"

    def test_ai_schema_violation_returns_original(self):
        """Response parses as JSON but fails the narratives schema."""
        timeline = self._timeline_with_steps(2)
        provider = _provider_with_response({"narratives": [1, 2]})  # ints, not strings
        result = rewrite_timeline_with_ai(timeline, provider)
        assert result.generated_by == "rules"

    def test_empty_timeline_skips_ai_call(self):
        empty = Timeline(file_type="unknown", steps=[], generated_by="rules")
        provider = MagicMock()
        result = rewrite_timeline_with_ai(empty, provider)
        provider.complete.assert_not_called()
        assert result.is_empty()

    def test_rewrite_prompt_contains_phase_labels(self):
        timeline = self._timeline_with_steps(2)
        prompt = _build_rewrite_prompt(timeline.steps)
        for step in timeline.steps:
            assert step.phase_label in prompt

    def test_rewrite_prompt_contains_evidence_refs(self):
        timeline = self._timeline_with_steps(2)
        prompt = _build_rewrite_prompt(timeline.steps)
        for step in timeline.steps:
            for ref in step.evidence_refs:
                assert ref in prompt
