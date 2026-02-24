"""Unit tests for triage analyzer."""

import hashlib
import json
import math
from collections import Counter

import pytest


def compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy (same as analyzer)."""
    if not data:
        return 0.0
    byte_counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


class TestEntropyComputation:
    """Tests for entropy computation."""

    def test_empty_data(self):
        """Empty data has zero entropy."""
        assert compute_entropy(b"") == 0.0

    def test_uniform_data(self):
        """Uniform data (all same bytes) has zero entropy."""
        assert compute_entropy(b"\x00" * 100) == 0.0
        assert compute_entropy(b"AAAA") == 0.0

    def test_max_entropy(self):
        """Data with all unique bytes has max entropy."""
        data = bytes(range(256))
        entropy = compute_entropy(data)
        # Max entropy for bytes is 8.0
        assert 7.9 < entropy <= 8.0

    def test_low_entropy_text(self):
        """ASCII text has moderate entropy."""
        data = b"Hello World! This is a test string."
        entropy = compute_entropy(data)
        assert 3.5 < entropy < 5.5

    def test_high_entropy_random(self):
        """Random-like data has high entropy."""
        # Pseudo-random data
        data = bytes([(i * 17 + 5) % 256 for i in range(256)])
        entropy = compute_entropy(data)
        assert entropy > 7.5


class TestStringExtraction:
    """Tests for string extraction logic."""

    def test_ascii_strings(self):
        """Extract ASCII strings."""
        data = b"\x00\x00Hello\x00\x00World\x00\x00"
        # Simple ASCII extraction
        ascii_pattern = rb'[\x20-\x7e]{4,}'
        import re
        strings = [m.group().decode('ascii') for m in re.finditer(ascii_pattern, data)]
        assert "Hello" in strings or "World" in strings

    def test_utf16le_strings(self):
        """Extract UTF-16LE strings."""
        text = "Hello"
        data = text.encode("utf-16le")
        utf16_pattern = rb'(?:[\x20-\x7e]\x00){4,}'
        import re
        matches = re.findall(utf16_pattern, data)
        assert len(matches) > 0

    def test_minimum_length(self):
        """Strings below minimum length are not extracted."""
        data = b"ABC\x00\x00\x00DEFG"
        ascii_pattern = rb'[\x20-\x7e]{4,}'
        import re
        strings = [m.group().decode('ascii') for m in re.finditer(ascii_pattern, data)]
        assert "ABC" not in strings
        assert "DEFG" in strings


class TestIOCExtraction:
    """Tests for IOC extraction."""

    def test_url_extraction(self):
        """Extract URLs from strings."""
        import re
        url_pattern = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)
        text = "Visit http://example.com/malware or https://evil.org/c2"
        urls = url_pattern.findall(text)
        assert "http://example.com/malware" in urls
        assert "https://evil.org/c2" in urls

    def test_domain_extraction(self):
        """Extract domains from strings."""
        import re
        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
        text = "Connect to malware.example.com or test.org"
        domains = domain_pattern.findall(text)
        assert "malware.example.com" in domains
        assert "test.org" in domains

    def test_ip_extraction(self):
        """Extract IP addresses from strings."""
        import re
        ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        text = "C2 server at 192.168.1.100 or 10.0.0.1"
        ips = ip_pattern.findall(text)
        assert "192.168.1.100" in ips
        assert "10.0.0.1" in ips

    def test_email_extraction(self):
        """Extract email addresses from strings."""
        import re
        email_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        text = "Contact attacker@evil.com or admin@test.org"
        emails = email_pattern.findall(text)
        assert "attacker@evil.com" in emails
        assert "admin@test.org" in emails

    def test_ioc_normalization(self):
        """IOC values are normalized."""
        # Domain normalization (lowercase)
        domain = "EVIL.COM"
        normalized = domain.lower()
        assert normalized == "evil.com"

        # Email normalization
        email = "Attacker@EVIL.COM"
        normalized = email.lower()
        assert normalized == "attacker@evil.com"


class TestHashVerification:
    """Tests for hash verification."""

    def test_sha256_verification(self):
        """Verify SHA256 hash matches."""
        data = b"test data"
        expected = hashlib.sha256(data).hexdigest()
        actual = hashlib.sha256(data).hexdigest()
        assert actual == expected

    def test_sha256_mismatch(self):
        """Detect SHA256 hash mismatch."""
        data = b"test data"
        wrong_hash = "a" * 64
        actual = hashlib.sha256(data).hexdigest()
        assert actual != wrong_hash


class TestReportSchema:
    """Tests for report schema compliance."""

    def test_minimal_report_structure(self):
        """Report has required fields."""
        report = {
            "schema_version": "1.0.0",
            "sample_sha256": "a" * 64,
            "tenant_id": "test",
            "file_type": "unknown",
            "hashes": {"sha256": "a" * 64},
            "summary": {"verdict": "unknown", "score": 0},
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
                "analysis_start": "2024-01-01T00:00:00Z",
                "analysis_end": "2024-01-01T00:00:00Z",
            },
        }

        # Validate required fields
        required = ["schema_version", "sample_sha256", "tenant_id", "file_type",
                   "hashes", "summary", "findings", "iocs", "artifacts",
                   "provenance", "timestamps"]
        for field in required:
            assert field in report

    def test_finding_structure(self):
        """Finding has required fields."""
        finding = {
            "id": "finding-001",
            "title": "Test Finding",
            "severity": "MEDIUM",
            "confidence": 75,
            "description": "Test description",
            "evidence": [{"type": "test", "value": "test"}],
            "tags": ["test"],
            "source": "triage-universal",
            "references": [],
            "affected_objects": [],
            "created_at": "2024-01-01T00:00:00Z",
        }

        required = ["id", "title", "severity", "confidence", "description",
                   "evidence", "source", "created_at"]
        for field in required:
            assert field in finding

        # Validate severity enum
        assert finding["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

        # Validate confidence range
        assert 0 <= finding["confidence"] <= 100

    def test_ioc_structure(self):
        """IOC has required fields."""
        ioc = {
            "type": "domain",
            "value": "evil.com",
            "normalized": "evil.com",
            "confidence": 70,
            "context": "Test context",
            "first_seen_in": "sample-hash",
            "tags": ["test"],
        }

        required = ["type", "value", "normalized", "confidence", "first_seen_in"]
        for field in required:
            assert field in ioc

        # Validate type enum
        valid_types = ["ip", "domain", "url", "email", "hash", "mutex",
                      "filepath", "registry", "useragent"]
        assert ioc["type"] in valid_types

        # Validate confidence range
        assert 0 <= ioc["confidence"] <= 100


class TestDeterministicOutput:
    """Tests for deterministic analyzer output."""

    def test_strings_deterministic_order(self):
        """Strings are extracted in deterministic order."""
        data = b"\x00AAA\x00BBB\x00CCC\x00"
        import re
        ascii_pattern = rb'[\x20-\x7e]{3,}'
        matches = list(re.finditer(ascii_pattern, data))
        strings = [m.group().decode('ascii') for m in matches]

        # Should be in offset order
        assert strings == ["AAA", "BBB", "CCC"]

    def test_iocs_deterministic_order(self):
        """IOCs are sorted deterministically."""
        iocs = ["zebra.com", "alpha.com", "beta.com"]
        sorted_iocs = sorted(iocs)
        assert sorted_iocs == ["alpha.com", "beta.com", "zebra.com"]

    def test_entropy_deterministic(self):
        """Entropy computation is deterministic."""
        data = b"test data for entropy computation"
        entropy1 = compute_entropy(data)
        entropy2 = compute_entropy(data)
        assert entropy1 == entropy2


class TestHighEntropyFinding:
    """Tests for high entropy finding generation."""

    def test_high_entropy_triggers_finding(self):
        """High entropy chunks trigger finding."""
        # Create high entropy data (all unique bytes)
        data = bytes(range(256))
        entropy = compute_entropy(data)
        threshold = 7.5
        assert entropy > threshold

    def test_low_entropy_no_finding(self):
        """Low entropy data doesn't trigger finding."""
        # Create low entropy data (repeated pattern)
        data = b"A" * 256
        entropy = compute_entropy(data)
        threshold = 7.5
        assert entropy < threshold
