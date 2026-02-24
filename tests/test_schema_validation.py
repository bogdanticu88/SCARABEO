"""Unit tests for runtime schema validation and merger fail-closed behaviour."""

import pytest

from scarabeo.validation import SchemaValidationError, validate_partial, validate_report
from services.worker.merger import merge_partial_outputs


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

SHA256 = "a" * 64
PIPELINE_HASH = "b" * 64
CONFIG_HASH = "c" * 64


def _valid_partial(analyzer_name="pe-analyzer"):
    return {
        "schema_version": "1.0.0",
        "analyzer_name": analyzer_name,
        "analyzer_version": "0.1.0",
        "findings": [],
        "iocs": [],
        "artifacts": [],
    }


def _valid_input_data():
    return {
        "sample_sha256": SHA256,
        "tenant_id": "tenant-123",
        "metadata": {
            "file_type": "PE32 executable",
            "analysis_start": "2024-01-15T10:00:00Z",
        },
    }


def _valid_report():
    return {
        "schema_version": "1.0.0",
        "sample_sha256": SHA256,
        "tenant_id": "tenant-123",
        "file_type": "PE32 executable",
        "hashes": {"sha256": SHA256},
        "summary": {"verdict": "unknown", "score": 0},
        "findings": [],
        "iocs": [],
        "artifacts": [],
        "provenance": {
            "pipeline_name": "standard",
            "pipeline_hash": PIPELINE_HASH,
            "engines": [{"name": "static", "version": "1.0.0"}],
            "config_hash": CONFIG_HASH,
            "deterministic_run": True,
        },
        "timestamps": {
            "analysis_start": "2024-01-15T10:00:00Z",
            "analysis_end": "2024-01-15T10:05:00Z",
        },
    }


# ---------------------------------------------------------------------------
# TestValidatePartial
# ---------------------------------------------------------------------------

class TestValidatePartial:

    def test_valid_partial_passes(self):
        validate_partial(_valid_partial(), "pe-analyzer")

    def test_missing_required_field_raises(self):
        data = _valid_partial()
        del data["analyzer_name"]
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_partial(data, "pe-analyzer")
        assert "partial" in str(exc_info.value)

    def test_invalid_severity_enum_raises(self):
        data = _valid_partial()
        data["findings"] = [
            {
                "id": "f-001",
                "title": "Test Finding",
                "severity": "INVALID",
                "confidence": 80,
                "description": "Test",
                "source": "pe-analyzer",
                "created_at": "2024-01-15T10:00:00Z",
            }
        ]
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_partial(data, "pe-analyzer")
        msg = str(exc_info.value)
        assert "partial" in msg
        assert "findings" in msg

    def test_missing_findings_key_raises(self):
        data = _valid_partial()
        del data["findings"]
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_partial(data, "pe-analyzer")
        assert "partial" in str(exc_info.value)

    def test_error_includes_analyzer_name(self):
        data = _valid_partial()
        del data["analyzer_name"]
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_partial(data, "pe-analyzer")
        assert "pe-analyzer" in str(exc_info.value)

    def test_error_includes_failing_path(self):
        data = _valid_partial()
        data["findings"] = [
            {
                "id": "f-001",
                "title": "Test",
                "severity": "INVALID",
                "confidence": 80,
                "description": "Test",
                "source": "pe-analyzer",
                "created_at": "2024-01-15T10:00:00Z",
            }
        ]
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_partial(data, "pe-analyzer")
        assert "path:" in str(exc_info.value)


# ---------------------------------------------------------------------------
# TestValidateReport
# ---------------------------------------------------------------------------

class TestValidateReport:

    def test_valid_report_passes(self):
        validate_report(_valid_report())

    def test_missing_required_field_raises(self):
        data = _valid_report()
        del data["tenant_id"]
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_report(data)
        assert "report" in str(exc_info.value)

    def test_invalid_verdict_raises(self):
        data = _valid_report()
        data["summary"]["verdict"] = "dangerous"
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_report(data)
        msg = str(exc_info.value)
        assert "report" in msg
        assert "summary" in msg

    def test_score_out_of_range_raises(self):
        data = _valid_report()
        data["summary"]["score"] = 150
        with pytest.raises(SchemaValidationError):
            validate_report(data)

    def test_error_includes_sample_sha256(self):
        data = _valid_report()
        del data["tenant_id"]
        with pytest.raises(SchemaValidationError) as exc_info:
            validate_report(data)
        # First 16 chars of the sha256 must appear in the error message
        assert SHA256[:16] in str(exc_info.value)


# ---------------------------------------------------------------------------
# TestMergerFailsClosed
# ---------------------------------------------------------------------------

class TestMergerFailsClosed:

    def test_invalid_partial_aborts_merge(self):
        bad_partial = _valid_partial()
        bad_partial["findings"] = [
            {
                "id": "f-001",
                "title": "Bad",
                "severity": "NOTVALID",
                "confidence": 80,
                "description": "Bad",
                "source": "pe-analyzer",
                "created_at": "2024-01-15T10:00:00Z",
            }
        ]
        with pytest.raises(SchemaValidationError):
            merge_partial_outputs(
                [bad_partial],
                _valid_input_data(),
                "standard",
                PIPELINE_HASH,
            )

    def test_valid_partials_produce_valid_report(self):
        # Provide hashes via triage-universal metadata so the merger can fill them
        partial = _valid_partial("triage-universal")
        partial["metadata"] = {"hashes": {"sha256": SHA256}}

        report = merge_partial_outputs(
            [partial],
            _valid_input_data(),
            "standard",
            PIPELINE_HASH,
        )
        # Round-trip: validate_report must not raise
        validate_report(report)

    def test_second_invalid_partial_aborts(self):
        good = _valid_partial("pe-analyzer")
        bad = _valid_partial("elf-analyzer")
        del bad["analyzer_version"]  # remove required field

        with pytest.raises(SchemaValidationError):
            merge_partial_outputs(
                [good, bad],
                _valid_input_data(),
                "standard",
                PIPELINE_HASH,
            )
