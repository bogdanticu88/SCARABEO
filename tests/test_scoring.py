"""Unit tests for scarabeo/scoring.py — deterministic evidence-based scoring.

Tests are grouped by dimension (persistence, exfiltration, stealth) plus
cross-cutting concerns (determinism, rationale format, confidence, overall).
No network calls, no filesystem I/O, no external services.
"""

import pytest

from scarabeo.scoring import (
    CategoryScore,
    ThreatScore,
    _score_exfiltration,
    _score_persistence,
    _score_stealth,
    score_report,
)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def _report(**kwargs) -> dict:
    """Minimal valid report dict. Override any key via kwargs."""
    base = {
        "sample_sha256": "a" * 64,
        "tenant_id": "test",
        "file_type": "pe",
        "findings": [],
        "iocs": [],
        "artifacts": [],
        "summary": {"verdict": "unknown", "score": 0},
    }
    base.update(kwargs)
    return base


def _finding(
    fid: str,
    title: str = "",
    severity: str = "HIGH",
    description: str = "",
    tags: list[str] | None = None,
    evidence: list[dict] | None = None,
) -> dict:
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "confidence": 80,
        "description": description,
        "tags": tags or [],
        "evidence": evidence or [],
        "source": "pe-analyzer",
    }


def _ioc(ioc_type: str, value: str, confidence: int = 80) -> dict:
    return {
        "type": ioc_type,
        "value": value,
        "normalized": value.lower(),
        "confidence": confidence,
        "first_seen_in": "sample",
    }


# ---------------------------------------------------------------------------
# TestPersistenceScoring
# ---------------------------------------------------------------------------

class TestPersistenceScoring:

    def test_empty_report_zero_score(self):
        result = _score_persistence(_report())
        assert result.score == 0
        assert result.confidence == 0
        assert result.rationale == []

    def test_registry_ioc_scores(self):
        r = _report(iocs=[_ioc("registry", "HKCU\\Software\\SomeApp\\config")])
        result = _score_persistence(r)
        assert result.score > 0

    def test_run_key_ioc_scores_higher_than_plain_registry(self):
        run_key_val = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
        plain_val = "HKCU\\Software\\SomeApp\\config"
        run_result = _score_persistence(_report(iocs=[_ioc("registry", run_key_val)]))
        plain_result = _score_persistence(_report(iocs=[_ioc("registry", plain_val)]))
        assert run_result.score > plain_result.score

    def test_multiple_registry_iocs_accumulate(self):
        iocs = [
            _ioc("registry", f"HKCU\\Software\\App{i}\\val") for i in range(3)
        ]
        result = _score_persistence(_report(iocs=iocs))
        single = _score_persistence(_report(iocs=[iocs[0]]))
        assert result.score > single.score

    def test_more_than_three_registry_iocs_capped_at_100(self):
        iocs = [
            _ioc("registry", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\App" + str(i))
            for i in range(10)
        ]
        result = _score_persistence(_report(iocs=iocs))
        assert result.score <= 100

    def test_schtask_keyword_in_title_scores(self):
        f = _finding("f-001", title="Registers scheduled task via schtasks")
        result = _score_persistence(_report(findings=[f]))
        assert result.score > 0

    def test_createservice_keyword_scores(self):
        f = _finding("f-002", description="Calls CreateService to install as a Windows service")
        result = _score_persistence(_report(findings=[f]))
        assert result.score > 0

    def test_startup_keyword_scores(self):
        f = _finding("f-003", description="Drops payload to Startup folder for autorun")
        result = _score_persistence(_report(findings=[f]))
        assert result.score > 0

    def test_run_key_string_in_evidence_scores(self):
        ev = [{"type": "string",
               "value": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware"}]
        f = _finding("f-004", title="Registry autorun", evidence=ev)
        result = _score_persistence(_report(findings=[f]))
        assert result.score > 0

    def test_low_severity_finding_scores_less_than_high(self):
        high_f = _finding("f-h", title="Creates scheduled task via schtasks", severity="HIGH")
        low_f  = _finding("f-l", title="Creates scheduled task via schtasks", severity="LOW")
        high_r = _score_persistence(_report(findings=[high_f]))
        low_r  = _score_persistence(_report(findings=[low_f]))
        assert high_r.score > low_r.score

    def test_rationale_contains_finding_id(self):
        f = _finding("f-001", title="schtasks persistence mechanism")
        result = _score_persistence(_report(findings=[f]))
        assert any("finding:f-001" in r for r in result.rationale)

    def test_rationale_contains_ioc_ref(self):
        val = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil"
        result = _score_persistence(_report(iocs=[_ioc("registry", val)]))
        assert any("ioc:registry:" in r for r in result.rationale)

    def test_confidence_zero_with_no_evidence(self):
        result = _score_persistence(_report())
        assert result.confidence == 0

    def test_confidence_increases_with_more_sources(self):
        one_ioc = _report(iocs=[_ioc("registry", "HKCU\\Software\\App\\val")])
        two_iocs = _report(iocs=[
            _ioc("registry", "HKCU\\Software\\App1\\val"),
            _ioc("registry", "HKCU\\Software\\App2\\val"),
        ])
        r1 = _score_persistence(one_ioc)
        r2 = _score_persistence(two_iocs)
        assert r2.confidence > r1.confidence

    def test_non_registry_ioc_does_not_score_persistence(self):
        r = _report(iocs=[_ioc("ip", "1.2.3.4"), _ioc("domain", "evil.com")])
        result = _score_persistence(r)
        assert result.score == 0


# ---------------------------------------------------------------------------
# TestExfiltrationScoring
# ---------------------------------------------------------------------------

class TestExfiltrationScoring:

    def test_empty_report_zero_score(self):
        result = _score_exfiltration(_report())
        assert result.score == 0
        assert result.confidence == 0

    def test_ip_ioc_scores(self):
        r = _report(iocs=[_ioc("ip", "192.0.2.1")])
        result = _score_exfiltration(r)
        assert result.score > 0

    def test_domain_ioc_scores(self):
        r = _report(iocs=[_ioc("domain", "c2.evil.example")])
        result = _score_exfiltration(r)
        assert result.score > 0

    def test_url_ioc_scores(self):
        r = _report(iocs=[_ioc("url", "http://evil.example/beacon")])
        result = _score_exfiltration(r)
        assert result.score > 0

    def test_ip_scores_higher_than_domain(self):
        ip_r     = _score_exfiltration(_report(iocs=[_ioc("ip", "192.0.2.1")]))
        domain_r = _score_exfiltration(_report(iocs=[_ioc("domain", "evil.example")]))
        assert ip_r.score >= domain_r.score

    def test_multiple_network_iocs_accumulate(self):
        iocs = [_ioc("ip", f"192.0.2.{i}") for i in range(4)]
        multi = _score_exfiltration(_report(iocs=iocs))
        single = _score_exfiltration(_report(iocs=[iocs[0]]))
        assert multi.score > single.score

    def test_network_iocs_capped_at_100(self):
        iocs = [_ioc("ip", f"10.0.0.{i}") for i in range(20)]
        result = _score_exfiltration(_report(iocs=iocs))
        assert result.score <= 100

    def test_registry_ioc_does_not_score_exfiltration(self):
        r = _report(iocs=[_ioc("registry", "HKCU\\Software\\App")])
        result = _score_exfiltration(r)
        assert result.score == 0

    def test_crypto_import_in_evidence_scores(self):
        ev = [{"type": "import", "value": "CryptEncrypt"}]
        f = _finding("f-001", title="Crypto API usage", evidence=ev)
        result = _score_exfiltration(_report(findings=[f]))
        assert result.score > 0

    def test_crypto_keyword_in_description_scores(self):
        f = _finding("f-002", description="Binary calls CryptDeriveKey to derive an encryption key")
        result = _score_exfiltration(_report(findings=[f]))
        assert result.score > 0

    def test_browser_artifact_path_scores(self):
        ev = [{"type": "string", "value": r"AppData\Local\Google\Chrome\User Data\Default\Login Data"}]
        f = _finding("f-003", title="Browser credential access", evidence=ev)
        result = _score_exfiltration(_report(findings=[f]))
        assert result.score > 0

    def test_browser_path_in_description_scores(self):
        f = _finding("f-004", description="Reads cookies.sqlite from Firefox profile")
        result = _score_exfiltration(_report(findings=[f]))
        assert result.score > 0

    def test_exfil_keyword_lsass_scores(self):
        f = _finding("f-005", title="LSASS memory access for credential dumping")
        result = _score_exfiltration(_report(findings=[f]))
        assert result.score > 0

    def test_exfil_keyword_keylog_scores(self):
        f = _finding("f-006", description="Installs a keylogger via SetWindowsHookEx")
        result = _score_exfiltration(_report(findings=[f]))
        assert result.score > 0

    def test_rationale_contains_ioc_ref(self):
        r = _report(iocs=[_ioc("ip", "192.0.2.1")])
        result = _score_exfiltration(r)
        assert any("ioc:ip:192.0.2.1" in ref for ref in result.rationale)

    def test_rationale_contains_finding_id(self):
        ev = [{"type": "import", "value": "CryptEncrypt"}]
        f = _finding("f-007", title="Crypto usage", evidence=ev)
        result = _score_exfiltration(_report(findings=[f]))
        assert any("finding:f-007" in ref for ref in result.rationale)

    def test_confidence_increases_with_more_sources(self):
        one = _report(iocs=[_ioc("ip", "192.0.2.1")])
        two = _report(iocs=[_ioc("ip", "192.0.2.1"), _ioc("domain", "evil.com")])
        assert _score_exfiltration(two).confidence > _score_exfiltration(one).confidence


# ---------------------------------------------------------------------------
# TestStealthScoring
# ---------------------------------------------------------------------------

class TestStealthScoring:

    def test_empty_report_zero_score(self):
        result = _score_stealth(_report())
        assert result.score == 0
        assert result.confidence == 0

    def test_anti_debug_keyword_scores(self):
        f = _finding("f-001", title="Calls IsDebuggerPresent to detect analysis")
        result = _score_stealth(_report(findings=[f]))
        assert result.score > 0

    def test_anti_vm_keyword_scores(self):
        f = _finding("f-002", description="Checks registry for VMware SVGA adapter presence")
        result = _score_stealth(_report(findings=[f]))
        assert result.score > 0

    def test_timing_keyword_rdtsc_scores(self):
        f = _finding("f-003", title="RDTSC timing check to detect sandboxes")
        result = _score_stealth(_report(findings=[f]))
        assert result.score > 0

    def test_packing_keyword_upx_scores(self):
        f = _finding("f-004", title="UPX-packed binary detected", tags=["packer"])
        result = _score_stealth(_report(findings=[f]))
        assert result.score > 0

    def test_obfuscation_keyword_scores(self):
        f = _finding("f-005", description="Heavily obfuscated code section detected")
        result = _score_stealth(_report(findings=[f]))
        assert result.score > 0

    def test_high_entropy_section_in_evidence_scores(self):
        ev = [{"type": "section", "value": ".text entropy=7.9 (high entropy)"}]
        f = _finding("f-006", title="High entropy section", evidence=ev)
        result = _score_stealth(_report(findings=[f]))
        assert result.score > 0

    def test_multiple_evasion_techniques_accumulate(self):
        multi = _finding(
            "f-007",
            title="IsDebuggerPresent anti-debug",
            description="Also checks for VMware and uses RDTSC timing",
        )
        single = _finding("f-008", title="IsDebuggerPresent anti-debug")
        multi_r  = _score_stealth(_report(findings=[multi]))
        single_r = _score_stealth(_report(findings=[single]))
        assert multi_r.score > single_r.score

    def test_low_severity_scores_less_than_critical(self):
        crit = _finding("f-h", title="IsDebuggerPresent evasion", severity="CRITICAL")
        low  = _finding("f-l", title="IsDebuggerPresent evasion", severity="LOW")
        assert _score_stealth(_report(findings=[crit])).score > \
               _score_stealth(_report(findings=[low])).score

    def test_score_capped_at_100(self):
        findings = [
            _finding(f"f-{i}", title="IsDebuggerPresent anti-debug VMware rdtsc upx obfuscat")
            for i in range(10)
        ]
        result = _score_stealth(_report(findings=findings))
        assert result.score <= 100

    def test_rationale_contains_finding_id(self):
        f = _finding("f-009", title="vmware detection via cpuid")
        result = _score_stealth(_report(findings=[f]))
        assert any("finding:f-009" in r for r in result.rationale)

    def test_non_evasion_finding_does_not_score(self):
        f = _finding("f-010", title="Opens handle to process memory", description="Reads remote PEB")
        result = _score_stealth(_report(findings=[f]))
        assert result.score == 0


# ---------------------------------------------------------------------------
# TestScoreReport (public API)
# ---------------------------------------------------------------------------

class TestScoreReport:

    def test_returns_threat_score(self):
        result = score_report(_report())
        assert isinstance(result, ThreatScore)
        assert isinstance(result.persistence, CategoryScore)
        assert isinstance(result.exfiltration, CategoryScore)
        assert isinstance(result.stealth, CategoryScore)

    def test_empty_report_all_zeros(self):
        result = score_report(_report())
        assert result.persistence.score == 0
        assert result.exfiltration.score == 0
        assert result.stealth.score == 0
        assert result.overall == 0

    def test_sample_sha256_propagated(self):
        sha = "b" * 64
        result = score_report(_report(sample_sha256=sha))
        assert result.sample_sha256 == sha

    def test_overall_is_weighted_combination(self):
        # Inject known scores by using a report with only network IOCs (exfil)
        r = _report(iocs=[_ioc("ip", "192.0.2.1")])
        result = score_report(r)
        # exfiltration > 0, persistence == 0, stealth == 0
        # overall = 0.40 * exfil + 0.35 * 0 + 0.25 * 0
        expected = int(0.40 * result.exfiltration.score)
        assert result.overall == expected

    def test_overall_capped_at_100(self):
        # Saturate all three dimensions
        iocs = (
            [_ioc("ip", f"192.0.2.{i}") for i in range(5)] +
            [_ioc("registry", f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\App{i}") for i in range(3)]
        )
        findings = [
            _finding("f-p", title="schtasks createservice winlogon startup"),
            _finding("f-e", title="lsass credential dump", description="cookies.sqlite keylog CryptEncrypt"),
            _finding("f-s", title="vmware isdebuggerpresent upx rdtsc obfuscat"),
        ]
        result = score_report(_report(iocs=iocs, findings=findings))
        assert result.overall <= 100

    def test_scoring_is_deterministic(self):
        r = _report(
            iocs=[_ioc("ip", "192.0.2.1"), _ioc("registry", "HKCU\\Software\\App")],
            findings=[_finding("f-001", title="schtasks IsDebuggerPresent upx")],
        )
        r1 = score_report(r)
        r2 = score_report(r)
        assert r1.persistence.score == r2.persistence.score
        assert r1.exfiltration.score == r2.exfiltration.score
        assert r1.stealth.score == r2.stealth.score
        assert r1.overall == r2.overall

    def test_type_error_on_non_dict(self):
        with pytest.raises(TypeError):
            score_report("not a dict")

    def test_all_scores_in_valid_range(self):
        iocs = [_ioc("ip", "192.0.2.1"), _ioc("registry", "HKCU\\Software\\App")]
        findings = [_finding("f-001", title="schtasks vmware CryptEncrypt upx")]
        result = score_report(_report(iocs=iocs, findings=findings))
        for cat in (result.persistence, result.exfiltration, result.stealth):
            assert 0 <= cat.score <= 100
            assert 0 <= cat.confidence <= 90
        assert 0 <= result.overall <= 100

    def test_confidence_never_exceeds_90(self):
        iocs = [_ioc("ip", f"192.0.2.{i}") for i in range(20)]
        result = score_report(_report(iocs=iocs))
        assert result.exfiltration.confidence <= 90

    def test_rationale_entries_are_strings(self):
        r = _report(
            iocs=[_ioc("ip", "192.0.2.1")],
            findings=[_finding("f-001", title="schtasks persistence vmware")],
        )
        result = score_report(r)
        for cat in (result.persistence, result.exfiltration, result.stealth):
            for entry in cat.rationale:
                assert isinstance(entry, str)

    def test_rationale_format_contains_dash_separator(self):
        """Each rationale entry must follow '{ref} — {reason}' format."""
        r = _report(iocs=[_ioc("ip", "192.0.2.1")])
        result = score_report(r)
        for entry in result.exfiltration.rationale:
            assert " — " in entry

    def test_combined_report_all_dimensions_score(self):
        """A report with evidence for all three dimensions produces non-zero scores."""
        r = _report(
            iocs=[_ioc("ip", "192.0.2.1"),
                  _ioc("registry", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil")],
            findings=[
                _finding("f-e", title="lsass credential dump CryptEncrypt"),
                _finding("f-s", title="vmware anti-vm IsDebuggerPresent upx packed"),
                _finding("f-p", title="schtasks scheduled task persistence"),
            ],
        )
        result = score_report(r)
        assert result.persistence.score > 0
        assert result.exfiltration.score > 0
        assert result.stealth.score > 0
        assert result.overall > 0
