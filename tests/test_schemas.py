"""Schema validation tests for Scarabeo contracts."""

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMAS_DIR = Path(__file__).parent.parent / "contracts" / "schemas"


def load_schema(name: str) -> dict:
    """Load a JSON schema by name."""
    schema_path = SCHEMAS_DIR / f"{name}.schema.json"
    with open(schema_path, "r") as f:
        return json.load(f)


def load_example(name: str) -> dict:
    """Load an example payload by name."""
    example_path = Path(__file__).parent / "examples" / f"{name}.json"
    with open(example_path, "r") as f:
        return json.load(f)


class TestInputSchema:
    """Tests for input.schema.json."""

    @pytest.fixture
    def schema(self):
        return load_schema("input")

    def test_valid_minimal_input(self, schema):
        payload = {
            "schema_version": "1.0.0",
            "sample_sha256": "a" * 64,
            "tenant_id": "tenant-123",
            "sample": {
                "filename": "test.exe",
                "size_bytes": 1024,
            },
        }
        Draft202012Validator(schema).validate(payload)

    def test_valid_full_input(self, schema):
        payload = {
            "schema_version": "1.0.0",
            "sample_sha256": "a" * 64,
            "tenant_id": "tenant-123",
            "sample": {
                "filename": "test.exe",
                "size_bytes": 1024,
                "mime_type": "application/x-dosexec",
                "storage_path": "s3://samples/a" * 64,
            },
            "options": {
                "timeout_seconds": 300,
                "engines": ["static", "dynamic"],
                "priority": "high",
            },
            "metadata": {"custom_field": "value"},
        }
        Draft202012Validator(schema).validate(payload)

    def test_invalid_missing_required(self, schema):
        payload = {
            "sample_sha256": "a" * 64,
            "tenant_id": "tenant-123",
        }
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(payload)

    def test_invalid_schema_version_format(self, schema):
        payload = {
            "schema_version": "1.0",
            "sample_sha256": "a" * 64,
            "tenant_id": "tenant-123",
            "sample": {"filename": "test.exe", "size_bytes": 1024},
        }
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(payload)

    def test_invalid_sha256_format(self, schema):
        payload = {
            "schema_version": "1.0.0",
            "sample_sha256": "invalid",
            "tenant_id": "tenant-123",
            "sample": {"filename": "test.exe", "size_bytes": 1024},
        }
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(payload)

    def test_invalid_priority_value(self, schema):
        payload = {
            "schema_version": "1.0.0",
            "sample_sha256": "a" * 64,
            "tenant_id": "tenant-123",
            "sample": {"filename": "test.exe", "size_bytes": 1024},
            "options": {"priority": "urgent"},
        }
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(payload)

    def test_additional_properties_rejected(self, schema):
        payload = {
            "schema_version": "1.0.0",
            "sample_sha256": "a" * 64,
            "tenant_id": "tenant-123",
            "sample": {"filename": "test.exe", "size_bytes": 1024},
            "extra_field": "not allowed",
        }
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(payload)


class TestFindingSchema:
    """Tests for finding.schema.json."""

    @pytest.fixture
    def schema(self):
        return load_schema("finding")

    def test_valid_minimal_finding(self, schema):
        payload = {
            "id": "finding-001",
            "title": "Suspicious API Call",
            "severity": "MEDIUM",
            "confidence": 75,
            "description": "Detected suspicious API call pattern",
            "evidence": [{"type": "string", "value": "CreateRemoteThread"}],
            "source": "static-analyzer",
            "created_at": "2024-01-15T10:30:00Z",
        }
        Draft202012Validator(schema).validate(payload)

    def test_valid_full_finding(self, schema):
        payload = {
            "id": "finding-001",
            "title": "Suspicious API Call",
            "severity": "HIGH",
            "confidence": 90,
            "description": "Detected process injection via CreateRemoteThread",
            "evidence": [
                {
                    "type": "api_call",
                    "value": "CreateRemoteThread",
                    "offset": 4096,
                    "length": 64,
                }
            ],
            "tags": ["injection", "evasion"],
            "source": "static-analyzer",
            "references": ["CVE-2024-1234", "https://attack.mitre.org/techniques/T1055/"],
            "affected_objects": [
                {"type": "process", "identifier": "pid:1234", "description": "Target process"}
            ],
            "created_at": "2024-01-15T10:30:00Z",
        }
        Draft202012Validator(schema).validate(payload)

    def test_invalid_severity_value(self, schema):
        payload = {
            "id": "finding-001",
            "title": "Test",
            "severity": "URGENT",
            "confidence": 75,
            "description": "Test",
            "evidence": [{"type": "string", "value": "test"}],
            "source": "test",
            "created_at": "2024-01-15T10:30:00Z",
        }
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(payload)

    def test_invalid_confidence_range(self, schema):
        payload = {
            "id": "finding-001",
            "title": "Test",
            "severity": "MEDIUM",
            "confidence": 150,
            "description": "Test",
            "evidence": [{"type": "string", "value": "test"}],
            "source": "test",
            "created_at": "2024-01-15T10:30:00Z",
        }
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(payload)


class TestIOCSchema:
    """Tests for ioc.schema.json."""

    @pytest.fixture
    def schema(self):
        return load_schema("ioc")

    def test_valid_ioc_ip(self, schema):
        payload = {
            "type": "ip",
            "value": "192.168.1.1",
            "normalized": "192.168.1.1",
            "confidence": 80,
            "first_seen_in": "sample-abc123",
        }
        Draft202012Validator(schema).validate(payload)

    def test_valid_ioc_full(self, schema):
        payload = {
            "type": "domain",
            "value": "malware.evil.com",
            "normalized": "malware.evil.com",
            "confidence": 95,
            "context": "C2 server domain",
            "first_seen_in": "sample-abc123",
            "tags": ["c2", "malware"],
        }
        Draft202012Validator(schema).validate(payload)

    def test_valid_all_ioc_types(self, schema):
        ioc_types = [
            ("ip", "192.168.1.1"),
            ("domain", "evil.com"),
            ("url", "http://evil.com/malware.exe"),
            ("email", "attacker@evil.com"),
            ("hash", "a" * 64),
            ("mutex", "Global\\MalwareMutex"),
            ("filepath", "C:\\Windows\\Temp\\malware.exe"),
            ("registry", "HKLM\\SOFTWARE\\Malware"),
            ("useragent", "Mozilla/5.0 (compatible; Malware)"),
        ]
        for ioc_type, value in ioc_types:
            payload = {
                "type": ioc_type,
                "value": value,
                "normalized": value,
                "confidence": 80,
                "first_seen_in": "sample-abc123",
            }
            Draft202012Validator(schema).validate(payload)

    def test_invalid_ioc_type(self, schema):
        payload = {
            "type": "invalid_type",
            "value": "test",
            "normalized": "test",
            "confidence": 80,
            "first_seen_in": "sample-abc123",
        }
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(payload)


class TestArtifactSchema:
    """Tests for artifact.schema.json."""

    @pytest.fixture
    def schema(self):
        return load_schema("artifact")

    def test_valid_minimal_artifact(self, schema):
        payload = {
            "type": "screenshot",
            "path": "/artifacts/screenshot_001.png",
            "sha256": "a" * 64,
            "produced_by": "dynamic-analyzer",
        }
        Draft202012Validator(schema).validate(payload)

    def test_valid_full_artifact(self, schema):
        payload = {
            "type": "extracted_file",
            "path": "/artifacts/extracted/config.bin",
            "sha256": "a" * 64,
            "mime": "application/octet-stream",
            "size_bytes": 2048,
            "produced_by": "unpacker",
            "safe_preview": "Base64 encoded preview...",
        }
        Draft202012Validator(schema).validate(payload)

    def test_invalid_sha256_format(self, schema):
        payload = {
            "type": "screenshot",
            "path": "/artifacts/screenshot.png",
            "sha256": "invalid",
            "produced_by": "dynamic-analyzer",
        }
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(payload)


class TestProvenanceSchema:
    """Tests for provenance.schema.json."""

    @pytest.fixture
    def schema(self):
        return load_schema("provenance")

    def test_valid_minimal_provenance(self, schema):
        payload = {
            "pipeline_name": "standard-analysis",
            "pipeline_hash": "a" * 64,
            "engines": [{"name": "static-analyzer", "version": "1.0.0"}],
            "config_hash": "b" * 64,
            "deterministic_run": True,
        }
        Draft202012Validator(schema).validate(payload)

    def test_valid_full_provenance(self, schema):
        payload = {
            "pipeline_name": "full-analysis",
            "pipeline_hash": "a" * 64,
            "engines": [
                {"name": "static-analyzer", "version": "1.0.0"},
                {"name": "dynamic-analyzer", "version": "2.0.0"},
            ],
            "container_image": "scarabeo/worker:1.0.0",
            "config_hash": "b" * 64,
            "deterministic_run": True,
        }
        Draft202012Validator(schema).validate(payload)

    def test_invalid_deterministic_run_false(self, schema):
        payload = {
            "pipeline_name": "test",
            "pipeline_hash": "a" * 64,
            "engines": [{"name": "test", "version": "1.0.0"}],
            "config_hash": "b" * 64,
            "deterministic_run": False,
        }
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(payload)


class TestReportSchema:
    """Tests for report.schema.json."""

    @pytest.fixture
    def schema(self):
        return load_schema("report")

    def test_valid_minimal_report(self, schema):
        payload = {
            "schema_version": "1.0.0",
            "sample_sha256": "a" * 64,
            "tenant_id": "tenant-123",
            "file_type": "PE32 executable",
            "hashes": {"sha256": "a" * 64},
            "summary": {"verdict": "malicious", "score": 85},
            "findings": [],
            "iocs": [],
            "artifacts": [],
            "provenance": {
                "pipeline_name": "standard",
                "pipeline_hash": "b" * 64,
                "engines": [{"name": "static", "version": "1.0.0"}],
                "config_hash": "c" * 64,
                "deterministic_run": True,
            },
            "timestamps": {
                "analysis_start": "2024-01-15T10:00:00Z",
                "analysis_end": "2024-01-15T10:05:00Z",
            },
        }
        Draft202012Validator(schema).validate(payload)

    def test_valid_full_report(self, schema):
        payload = {
            "schema_version": "1.0.0",
            "sample_sha256": "a" * 64,
            "tenant_id": "tenant-123",
            "file_type": "PE32 executable",
            "hashes": {
                "md5": "d" * 32,
                "sha1": "e" * 40,
                "sha256": "a" * 64,
                "sha512": "f" * 128,
                "ssdeep": "12288:abc:def",
                "tlsh": "T1ABC123",
            },
            "summary": {
                "verdict": "malicious",
                "score": 95,
                "threat_family": "Emotet",
                "detection_names": ["Trojan.Emotet", "HEUR:Emotet"],
            },
            "findings": [
                {
                    "id": "finding-001",
                    "title": "Suspicious Import",
                    "severity": "MEDIUM",
                    "confidence": 80,
                    "description": "Suspicious API imports detected",
                    "evidence": [{"type": "import", "value": "VirtualAllocEx"}],
                    "source": "static-analyzer",
                    "created_at": "2024-01-15T10:02:00Z",
                }
            ],
            "iocs": [
                {
                    "type": "domain",
                    "value": "c2.malware.com",
                    "normalized": "c2.malware.com",
                    "confidence": 90,
                    "first_seen_in": "sample-abc",
                }
            ],
            "artifacts": [
                {
                    "type": "screenshot",
                    "path": "/artifacts/screen.png",
                    "sha256": "g" * 64,
                    "produced_by": "dynamic-analyzer",
                }
            ],
            "provenance": {
                "pipeline_name": "full-analysis",
                "pipeline_hash": "b" * 64,
                "engines": [
                    {"name": "static-analyzer", "version": "1.0.0"},
                    {"name": "dynamic-analyzer", "version": "2.0.0"},
                ],
                "container_image": "scarabeo/worker:1.0.0",
                "config_hash": "c" * 64,
                "deterministic_run": True,
            },
            "timestamps": {
                "analysis_start": "2024-01-15T10:00:00Z",
                "analysis_end": "2024-01-15T10:10:00Z",
            },
        }
        Draft202012Validator(schema).validate(payload)

    def test_invalid_verdict_value(self, schema):
        payload = {
            "schema_version": "1.0.0",
            "sample_sha256": "a" * 64,
            "tenant_id": "tenant-123",
            "file_type": "PE32",
            "hashes": {"sha256": "a" * 64},
            "summary": {"verdict": "dangerous", "score": 85},
            "findings": [],
            "iocs": [],
            "artifacts": [],
            "provenance": {
                "pipeline_name": "test",
                "pipeline_hash": "b" * 64,
                "engines": [{"name": "test", "version": "1.0.0"}],
                "config_hash": "c" * 64,
                "deterministic_run": True,
            },
            "timestamps": {
                "analysis_start": "2024-01-15T10:00:00Z",
                "analysis_end": "2024-01-15T10:05:00Z",
            },
        }
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(payload)

    def test_invalid_score_range(self, schema):
        payload = {
            "schema_version": "1.0.0",
            "sample_sha256": "a" * 64,
            "tenant_id": "tenant-123",
            "file_type": "PE32",
            "hashes": {"sha256": "a" * 64},
            "summary": {"verdict": "malicious", "score": 150},
            "findings": [],
            "iocs": [],
            "artifacts": [],
            "provenance": {
                "pipeline_name": "test",
                "pipeline_hash": "b" * 64,
                "engines": [{"name": "test", "version": "1.0.0"}],
                "config_hash": "c" * 64,
                "deterministic_run": True,
            },
            "timestamps": {
                "analysis_start": "2024-01-15T10:00:00Z",
                "analysis_end": "2024-01-15T10:05:00Z",
            },
        }
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(payload)


class TestSchemaCrossReferences:
    """Tests for schema cross-references."""

    def test_report_contains_valid_finding(self):
        report_schema = load_schema("report")
        finding_schema = load_schema("finding")

        report = {
            "schema_version": "1.0.0",
            "sample_sha256": "a" * 64,
            "tenant_id": "tenant-123",
            "file_type": "PE32",
            "hashes": {"sha256": "a" * 64},
            "summary": {"verdict": "malicious", "score": 85},
            "findings": [
                {
                    "id": "f1",
                    "title": "Test",
                    "severity": "HIGH",
                    "confidence": 80,
                    "description": "Test",
                    "evidence": [{"type": "test", "value": "test"}],
                    "source": "test",
                    "created_at": "2024-01-15T10:00:00Z",
                }
            ],
            "iocs": [],
            "artifacts": [],
            "provenance": {
                "pipeline_name": "test",
                "pipeline_hash": "b" * 64,
                "engines": [{"name": "test", "version": "1.0.0"}],
                "config_hash": "c" * 64,
                "deterministic_run": True,
            },
            "timestamps": {
                "analysis_start": "2024-01-15T10:00:00Z",
                "analysis_end": "2024-01-15T10:05:00Z",
            },
        }

        validator = Draft202012Validator(
            report_schema,
            resolver=Draft202012Validator(
                {"$defs": {"finding": finding_schema}}
            ).resolver,
        )
        validator.validate(report)
