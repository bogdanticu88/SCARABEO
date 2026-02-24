"""Unit tests for analyzer router and merger."""

import pytest
from services.worker.router import get_analyzers_for_file_type, get_analyzer_container, get_analyzer_version
from services.worker.merger import merge_partial_outputs, calculate_verdict


class TestAnalyzerRouter:
    """Tests for analyzer routing."""

    def test_triage_pipeline_pe(self):
        """Triage pipeline runs only universal + similarity for PE."""
        analyzers = get_analyzers_for_file_type("pe", "triage")
        names = [a["name"] for a in analyzers]
        assert "triage-universal" in names
        assert "similarity-analyzer" in names
        assert "pe-analyzer" not in names

    def test_deep_pipeline_pe(self):
        """Deep pipeline runs PE analyzer for PE files."""
        analyzers = get_analyzers_for_file_type("pe", "deep")
        names = [a["name"] for a in analyzers]
        assert "triage-universal" in names
        assert "pe-analyzer" in names
        assert "similarity-analyzer" in names
        assert "elf-analyzer" not in names

    def test_deep_pipeline_elf(self):
        """Deep pipeline runs ELF analyzer for ELF files."""
        analyzers = get_analyzers_for_file_type("elf", "deep")
        names = [a["name"] for a in analyzers]
        assert "elf-analyzer" in names
        assert "pe-analyzer" not in names

    def test_deep_pipeline_script(self):
        """Deep pipeline runs script analyzer for script files."""
        analyzers = get_analyzers_for_file_type("script", "deep")
        names = [a["name"] for a in analyzers]
        assert "script-analyzer" in names

    def test_deep_pipeline_document(self):
        """Deep pipeline runs doc analyzer for document files."""
        analyzers = get_analyzers_for_file_type("document", "deep")
        names = [a["name"] for a in analyzers]
        assert "doc-analyzer" in names

    def test_deep_pipeline_archive(self):
        """Deep pipeline runs archive analyzer for archive files."""
        analyzers = get_analyzers_for_file_type("archive", "deep")
        names = [a["name"] for a in analyzers]
        assert "archive-analyzer" in names

    def test_yara_disabled_by_default(self):
        """YARA analyzer is disabled without feature flag."""
        analyzers = get_analyzers_for_file_type("pe", "deep", feature_flags={})
        names = [a["name"] for a in analyzers]
        assert "yara-analyzer" not in names

    def test_yara_enabled_with_flag(self):
        """YARA analyzer is enabled with feature flag."""
        analyzers = get_analyzers_for_file_type("pe", "deep", feature_flags={"YARA_ENABLED": True})
        names = [a["name"] for a in analyzers]
        assert "yara-analyzer" in names

    def test_archive_pipeline(self):
        """Archive pipeline runs correct analyzers."""
        analyzers = get_analyzers_for_file_type("archive", "archive")
        names = [a["name"] for a in analyzers]
        assert "triage-universal" in names
        assert "archive-analyzer" in names

    def test_get_analyzer_container(self):
        """Get container image for analyzer."""
        assert get_analyzer_container("pe-analyzer") == "scarabeo/pe-analyzer:latest"
        assert get_analyzer_container("unknown") is None

    def test_get_analyzer_version(self):
        """Get version for analyzer."""
        assert get_analyzer_version("pe-analyzer") == "0.1.0"
        assert get_analyzer_version("unknown") == "unknown"


class TestReportMerger:
    """Tests for report merging."""

    def test_merge_empty_partials(self):
        """Merge with no partials produces minimal report."""
        input_data = {
            "sample_sha256": "a" * 64,
            "tenant_id": "test",
            "metadata": {"file_type": "pe"},
        }
        report = merge_partial_outputs([], input_data, "triage", "b" * 64)
        assert report["sample_sha256"] == input_data["sample_sha256"]
        assert report["findings"] == []
        assert report["iocs"] == []

    def test_merge_single_partial(self):
        """Merge single partial output."""
        input_data = {
            "sample_sha256": "a" * 64,
            "tenant_id": "test",
            "metadata": {"file_type": "pe"},
        }
        partial = {
            "schema_version": "1.0.0",
            "analyzer_name": "test-analyzer",
            "analyzer_version": "1.0.0",
            "findings": [
                {
                    "id": "f1",
                    "title": "Test",
                    "severity": "MEDIUM",
                    "confidence": 75,
                    "description": "Test",
                    "evidence": [{"type": "string", "value": "test"}],
                    "source": "test",
                    "created_at": "2024-01-01T00:00:00Z",
                }
            ],
            "iocs": [],
            "artifacts": [],
        }
        report = merge_partial_outputs([partial], input_data, "triage", "b" * 64)
        assert len(report["findings"]) == 1
        assert report["findings"][0]["id"] == "f1"
        assert len(report["provenance"]["engines"]) == 1

    def test_merge_multiple_partials(self):
        """Merge multiple partial outputs."""
        input_data = {
            "sample_sha256": "a" * 64,
            "tenant_id": "test",
            "metadata": {"file_type": "pe"},
        }
        partials = [
            {
                "schema_version": "1.0.0",
                "analyzer_name": "analyzer-a",
                "analyzer_version": "1.0.0",
                "findings": [
                    {
                        "id": "f1",
                        "title": "A",
                        "severity": "LOW",
                        "confidence": 50,
                        "description": "A",
                        "evidence": [{"type": "string", "value": "a"}],
                        "source": "a",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ],
                "iocs": [],
                "artifacts": [],
            },
            {
                "schema_version": "1.0.0",
                "analyzer_name": "analyzer-b",
                "analyzer_version": "1.0.0",
                "findings": [
                    {
                        "id": "f2",
                        "title": "B",
                        "severity": "HIGH",
                        "confidence": 80,
                        "description": "B",
                        "evidence": [{"type": "string", "value": "b"}],
                        "source": "b",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ],
                "iocs": [],
                "artifacts": [],
            },
        ]
        report = merge_partial_outputs(partials, input_data, "deep", "b" * 64)
        assert len(report["findings"]) == 2
        assert len(report["provenance"]["engines"]) == 2

    def test_merge_deterministic_ordering(self):
        """Merge produces deterministic ordering."""
        input_data = {
            "sample_sha256": "a" * 64,
            "tenant_id": "test",
            "metadata": {"file_type": "pe"},
        }
        partials = [
            {
                "schema_version": "1.0.0",
                "analyzer_name": "z-analyzer",
                "analyzer_version": "1.0.0",
                "findings": [
                    {
                        "id": "f2",
                        "title": "Z",
                        "severity": "LOW",
                        "confidence": 50,
                        "description": "Z",
                        "evidence": [{"type": "string", "value": "z"}],
                        "source": "z",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ],
                "iocs": [],
                "artifacts": [],
            },
            {
                "schema_version": "1.0.0",
                "analyzer_name": "a-analyzer",
                "analyzer_version": "1.0.0",
                "findings": [
                    {
                        "id": "f1",
                        "title": "A",
                        "severity": "HIGH",
                        "confidence": 80,
                        "description": "A",
                        "evidence": [{"type": "string", "value": "a"}],
                        "source": "a",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ],
                "iocs": [],
                "artifacts": [],
            },
        ]
        report1 = merge_partial_outputs(partials, input_data, "deep", "b" * 64)
        report2 = merge_partial_outputs(list(reversed(partials)), input_data, "deep", "b" * 64)

        # Findings should be in same order regardless of input order
        assert report1["findings"] == report2["findings"]
        assert report1["provenance"]["engines"] == report2["provenance"]["engines"]


class TestVerdictCalculation:
    """Tests for verdict calculation."""

    def test_no_findings_unknown(self):
        """No findings results in unknown verdict."""
        verdict, score = calculate_verdict([])
        assert verdict == "unknown"
        assert score == 0

    def test_low_severity_finding(self):
        """Low severity finding results in benign verdict."""
        findings = [{"severity": "LOW", "confidence": 50}]
        verdict, score = calculate_verdict(findings)
        assert verdict == "benign"
        assert score > 0

    def test_medium_severity_finding(self):
        """Medium severity finding results in suspicious verdict."""
        findings = [{"severity": "MEDIUM", "confidence": 80}]
        verdict, score = calculate_verdict(findings)
        assert verdict == "suspicious"

    def test_high_severity_finding(self):
        """High severity finding results in malicious verdict."""
        findings = [{"severity": "HIGH", "confidence": 90}]
        verdict, score = calculate_verdict(findings)
        assert verdict == "malicious"

    def test_critical_severity_finding(self):
        """Critical severity finding results in malicious verdict with high score."""
        findings = [{"severity": "CRITICAL", "confidence": 95}]
        verdict, score = calculate_verdict(findings)
        assert verdict == "malicious"
        assert score >= 75

    def test_multiple_findings_accumulation(self):
        """Multiple findings accumulate score."""
        findings = [
            {"severity": "LOW", "confidence": 50},
            {"severity": "MEDIUM", "confidence": 70},
            {"severity": "HIGH", "confidence": 80},
        ]
        verdict, score = calculate_verdict(findings)
        assert verdict == "malicious"
        assert score > 30

    def test_score_capped_at_100(self):
        """Score is capped at 100."""
        findings = [{"severity": "CRITICAL", "confidence": 100}] * 10
        verdict, score = calculate_verdict(findings)
        assert score == 100
