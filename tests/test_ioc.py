"""Comprehensive tests for scarabeo/ioc.py.

Covers: extraction of all IOC types, normalization, false-positive filtering,
deduplication, and deterministic sorting.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from scarabeo.ioc import (
    deduplicate_ioc_records,
    extract_iocs,
    make_ioc_records,
    normalize_ioc,
    sort_ioc_records,
)


# ── Helper ────────────────────────────────────────────────────────────────────

def _ioc(text: str, **kwargs) -> dict[str, list[str]]:
    return extract_iocs(text, **kwargs)


# ── URL extraction ─────────────────────────────────────────────────────────────

class TestURLExtraction:
    def test_basic_http(self):
        result = _ioc("connecting to http://malware.com/c2/gate")
        assert "http://malware.com/c2/gate" in result["url"]

    def test_basic_https(self):
        result = _ioc("https://evil.ru/payload.exe loaded")
        assert "https://evil.ru/payload.exe" in result["url"]

    def test_ftp_url(self):
        result = _ioc("download from ftp://files.evil.net/dropper")
        assert any("ftp://" in u for u in result["url"])

    def test_url_with_query_string(self):
        result = _ioc("beacon to https://c2.example.com/check?id=abc123&v=2")
        assert any("id=abc123" in u for u in result["url"])

    def test_url_with_port(self):
        result = _ioc("http://1.2.3.4:8080/command")
        assert any("8080" in u for u in result["url"])

    def test_trailing_punctuation_stripped(self):
        # Trailing period is punctuation, not part of URL
        result = _ioc('URL is "https://malware.io/c2".')
        urls = result["url"]
        assert all(not u.endswith(".") for u in urls)
        assert any("malware.io" in u for u in urls)

    def test_url_case_preserved(self):
        # Raw URL preserved as found; normalization happens separately
        result = _ioc("https://MALWARE.COM/Path")
        assert any("MALWARE.COM" in u for u in result["url"])

    def test_multiple_urls_deduplicated(self):
        text = "https://evil.com/a https://evil.com/a https://evil.com/b"
        result = _ioc(text)
        url_set = set(result["url"])
        assert len(url_set) == len(result["url"]), "Duplicate URLs must be de-duped"

    def test_url_not_also_domain(self):
        result = _ioc("https://malware.com/c2")
        # malware.com host should not also appear in the domain list
        hosts = {u.split("://")[1].split("/")[0].split(":")[0].lower()
                 for u in result["url"]}
        for h in hosts:
            assert h not in result["domain"], \
                f"URL host {h!r} must not appear in domain list"

    def test_url_sorted_deterministically(self):
        text = "https://z.com/ https://a.com/ https://m.com/"
        result = _ioc(text)
        normalized = [normalize_ioc("url", u) for u in result["url"]]
        assert normalized == sorted(normalized)


# ── Domain extraction ─────────────────────────────────────────────────────────

class TestDomainExtraction:
    def test_basic_domain(self):
        result = _ioc("calls home to malware.ru for instructions")
        assert "malware.ru" in result["domain"]

    def test_subdomain_extracted(self):
        result = _ioc("beacon to api.c2.attacker.net")
        assert any("attacker.net" in d or "c2.attacker.net" in d
                   for d in result["domain"])

    def test_extension_tld_filtered(self):
        # kernel32.dll must NOT be treated as a domain
        result = _ioc("imports kernel32.dll and ntdll.dll")
        dll_domains = [d for d in result["domain"] if d.endswith(".dll")]
        assert dll_domains == [], f"DLL file extensions must not be domains: {dll_domains}"

    def test_exe_extension_filtered(self):
        result = _ioc("loaded payload.exe from disk")
        exe_domains = [d for d in result["domain"] if d.endswith(".exe")]
        assert exe_domains == []

    def test_multiple_extension_fps(self):
        """File extensions that look like TLDs must all be filtered."""
        fps = [
            "loader.sys", "injector.ps1", "macro.vbs",
            "dropper.bat", "rootkit.drv", "hook.ocx",
        ]
        text = " ".join(fps)
        result = _ioc(text)
        for fp in fps:
            assert fp not in result["domain"], f"{fp} should not be a domain"

    def test_private_ip_not_domain(self):
        result = _ioc("connect to 192.168.1.1 for C2")
        assert "192.168.1.1" not in result["domain"]

    def test_domain_not_in_email_too(self):
        result = _ioc("contact admin@evil.org for more info")
        # evil.org appears as part of an email; it should not also be extracted
        # as a standalone domain (email handling takes priority)
        assert "evil.org" not in result["domain"]

    def test_domain_sorted_deterministically(self):
        text = "z.com m.com a.com q.net"
        result = _ioc(text)
        assert result["domain"] == sorted(result["domain"])

    def test_single_label_not_domain(self):
        # "localhost" has no TLD → not a domain
        result = _ioc("connect to localhost for debugging")
        assert "localhost" not in result["domain"]

    def test_numeric_tld_filtered(self):
        # 1.2.3.4 — pure-numeric "TLD" (4) should not match as a domain
        result = _ioc("1.2.3.4")
        assert "1.2.3.4" not in result["domain"]

    def test_two_char_tld_valid(self):
        result = _ioc("download from malware.ru updates")
        assert "malware.ru" in result["domain"]


# ── IP extraction ─────────────────────────────────────────────────────────────

class TestIPExtraction:
    def test_public_ip_extracted(self):
        result = _ioc("beacon to 1.2.3.4 port 443")
        assert "1.2.3.4" in result["ip"]

    def test_well_known_dns_extracted(self):
        result = _ioc("using 8.8.8.8 for DNS")
        assert "8.8.8.8" in result["ip"]

    def test_private_ip_filtered_by_default(self):
        result = _ioc("connect to 192.168.10.5")
        assert "192.168.10.5" not in result["ip"]

    def test_loopback_filtered(self):
        result = _ioc("listen on 127.0.0.1:8080")
        assert "127.0.0.1" not in result["ip"]

    def test_broadcast_filtered(self):
        result = _ioc("send to 255.255.255.255")
        assert "255.255.255.255" not in result["ip"]

    def test_zero_ip_filtered(self):
        result = _ioc("0.0.0.0 default route")
        assert "0.0.0.0" not in result["ip"]

    def test_private_ip_included_when_flag_set(self):
        result = extract_iocs("192.168.1.1", include_private_ips=True)
        assert "192.168.1.1" in result["ip"]

    def test_link_local_filtered(self):
        result = _ioc("link-local 169.254.1.1")
        assert "169.254.1.1" not in result["ip"]

    def test_ten_net_filtered(self):
        result = _ioc("10.0.0.1 internal host")
        assert "10.0.0.1" not in result["ip"]

    def test_ip_sorted(self):
        result = _ioc("9.9.9.9 1.1.1.1 8.8.8.8")
        norms = [normalize_ioc("ip", ip) for ip in result["ip"]]
        assert norms == sorted(norms)


# ── Email extraction ──────────────────────────────────────────────────────────

class TestEmailExtraction:
    def test_basic_email(self):
        result = _ioc("send results to attacker@evil.com")
        assert "attacker@evil.com" in result["email"]

    def test_email_with_plus(self):
        result = _ioc("reply-to: victim+tag@domain.net")
        assert "victim+tag@domain.net" in result["email"]

    def test_multiple_emails_deduplicated(self):
        text = "cc: a@b.com a@b.com bcc: a@b.com"
        result = _ioc(text)
        assert result["email"].count("a@b.com") == 1

    def test_email_extracted_from_noise(self):
        result = _ioc("POST /exfil?to=user@malicious.net&data=stolen")
        assert any("malicious.net" in e for e in result["email"])

    def test_email_sorted(self):
        result = _ioc("z@z.com a@a.com m@m.com")
        assert result["email"] == sorted(result["email"])


# ── Windows path extraction ───────────────────────────────────────────────────

class TestWindowsPathExtraction:
    def test_drive_letter_path(self):
        result = _ioc(r"writing to C:\Users\Admin\AppData\Roaming\mal\config.dat")
        fps = result["filepath"]
        assert any(r"C:\Users\Admin" in p or "c:\\users\\admin" in p.lower()
                   for p in fps)

    def test_env_var_path(self):
        result = _ioc(r"dropping to %APPDATA%\malware\dropper.exe")
        fps = result["filepath"]
        assert any("%APPDATA%" in p for p in fps)

    def test_unc_path(self):
        result = _ioc(r"reading \\server\share\payload.exe remotely")
        fps = result["filepath"]
        assert any("server" in p.lower() for p in fps)

    def test_system_path_extracted(self):
        result = _ioc(r"C:\Windows\System32\cmd.exe /c whoami")
        fps = result["filepath"]
        assert any("system32" in p.lower() for p in fps)

    def test_path_not_extracted_when_disabled(self):
        result = extract_iocs(r"C:\malware\payload.exe", include_filepaths=False)
        assert result["filepath"] == []


# ── Unix path extraction ──────────────────────────────────────────────────────

class TestUnixPathExtraction:
    def test_etc_passwd(self):
        result = _ioc("reading /etc/passwd for usernames")
        fps = result["filepath"]
        assert any("/etc/passwd" in p for p in fps)

    def test_tmp_path(self):
        result = _ioc("dropped to /tmp/malware.sh and executed")
        fps = result["filepath"]
        assert any("/tmp/malware.sh" in p for p in fps)

    def test_usr_bin_path(self):
        result = _ioc("exec /usr/bin/curl http://evil.com/download")
        fps = result["filepath"]
        assert any("/usr/bin/curl" in p for p in fps)

    def test_root_only_not_extracted(self):
        # "/" alone is not a useful IOC
        result = _ioc("splitting on /")
        fps = result["filepath"]
        assert "/" not in fps

    def test_windows_path_not_matched_by_nix_pattern(self):
        # C:\Windows should not match unix pattern
        result = _ioc(r"C:\Windows\System32\cmd.exe")
        fps = result["filepath"]
        # Should only appear once (as windows path, not twice)
        assert fps.count(r"C:\Windows\System32\cmd.exe") <= 1


# ── Registry key extraction ───────────────────────────────────────────────────

class TestRegistryKeyExtraction:
    def test_full_hklm_path(self):
        result = _ioc(
            r"writing HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        regs = result["registry"]
        assert any("CurrentVersion" in r or "currentversion" in r.lower()
                   for r in regs)

    def test_short_hklm(self):
        result = _ioc(r"persistence via HKLM\SOFTWARE\Malware\Config")
        regs = result["registry"]
        assert any("HKLM" in r or "HKEY_LOCAL_MACHINE" in normalize_ioc("registry", r)
                   for r in regs)

    def test_hkcu_path(self):
        result = _ioc(r"HKCU\Software\Backdoor\Settings")
        regs = result["registry"]
        assert regs != []

    def test_incomplete_path_not_extracted(self):
        # Path without root key should not be extracted
        result = _ioc(r"SOFTWARE\Microsoft\Windows without a root key")
        regs = result["registry"]
        # None should match since there's no HKLM/HKCU prefix
        assert not any("SOFTWARE\\Microsoft" in r and not r.startswith("H") for r in regs)

    def test_registry_not_extracted_when_disabled(self):
        result = extract_iocs(
            r"HKLM\SOFTWARE\Malware", include_registry=False
        )
        assert result["registry"] == []

    def test_registry_sorted(self):
        text = (
            r"HKCU\Software\Z "
            r"HKCU\Software\A "
            r"HKLM\Software\M"
        )
        result = _ioc(text)
        norms = [normalize_ioc("registry", r) for r in result["registry"]]
        assert norms == sorted(norms)


# ── Normalization ─────────────────────────────────────────────────────────────

class TestNormalizeIOC:
    def test_url_scheme_lowercased(self):
        assert normalize_ioc("url", "HTTPS://MALWARE.COM/path") == "https://malware.com/path"

    def test_url_trailing_slash_stripped(self):
        n = normalize_ioc("url", "https://malware.com/c2/")
        assert not n.endswith("/") or n == "https://malware.com/"

    def test_url_percent_decoded(self):
        n = normalize_ioc("url", "https://malware.com/path%20with%20space")
        assert "path with space" in n or "%20" not in n

    def test_url_fragment_stripped(self):
        n = normalize_ioc("url", "https://malware.com/page#anchor")
        assert "#" not in n

    def test_domain_lowercased(self):
        assert normalize_ioc("domain", "EVIL.COM") == "evil.com"

    def test_domain_trailing_dot_stripped(self):
        assert normalize_ioc("domain", "evil.com.") == "evil.com"

    def test_ip_canonical_form(self):
        # Valid IP normalizes to canonical string representation
        n = normalize_ioc("ip", "8.8.8.8")
        assert n == "8.8.8.8"
        # IPv4 with max octet values
        n2 = normalize_ioc("ip", "255.128.0.1")
        assert n2 == "255.128.0.1"

    def test_email_lowercased(self):
        assert normalize_ioc("email", "ATTACKER@EVIL.COM") == "attacker@evil.com"

    def test_filepath_normalized(self):
        n = normalize_ioc("filepath", r"C:\Users\Admin\APPDATA")
        assert n == r"c:\users\admin\appdata"

    def test_filepath_forward_slash_normalized(self):
        n = normalize_ioc("filepath", "C:/Users/Admin/file.exe")
        assert "\\" in n
        assert "/" not in n

    def test_registry_root_expanded(self):
        n = normalize_ioc("registry", r"HKLM\SOFTWARE\Run")
        assert n.startswith("HKEY_LOCAL_MACHINE")

    def test_registry_hkcu_expanded(self):
        n = normalize_ioc("registry", r"HKCU\Software\X")
        assert n.startswith("HKEY_CURRENT_USER")

    def test_registry_path_lowercased(self):
        n = normalize_ioc("registry", r"HKLM\SOFTWARE\Microsoft")
        assert n == r"HKEY_LOCAL_MACHINE\software\microsoft"

    def test_unknown_type_passthrough(self):
        assert normalize_ioc("mutex", "Global\\SomeMutex") == "Global\\SomeMutex"


# ── make_ioc_records ──────────────────────────────────────────────────────────

class TestMakeIOCRecords:
    def test_schema_required_fields(self):
        iocs = {"url": ["https://evil.com/c2"], "domain": [], "ip": [],
                "email": [], "filepath": [], "registry": []}
        records = make_ioc_records(iocs, "a" * 64)
        required = {"type", "value", "normalized", "confidence", "first_seen_in"}
        for r in records:
            missing = required - set(r.keys())
            assert not missing, f"Missing fields: {missing}"

    def test_confidence_in_range(self):
        iocs = extract_iocs("https://evil.com a@b.com 1.2.3.4")
        records = make_ioc_records(iocs, "b" * 64)
        for r in records:
            assert 0 <= r["confidence"] <= 100

    def test_first_seen_in_propagated(self):
        sha = "c" * 64
        iocs = extract_iocs("https://evil.com")
        records = make_ioc_records(iocs, sha)
        for r in records:
            assert r["first_seen_in"] == sha

    def test_url_tags_contain_network(self):
        iocs = {"url": ["https://evil.com"], "domain": [], "ip": [],
                "email": [], "filepath": [], "registry": []}
        records = make_ioc_records(iocs, "a" * 64)
        url_recs = [r for r in records if r["type"] == "url"]
        assert all("network" in r["tags"] for r in url_recs)

    def test_registry_tags_contain_persistence(self):
        iocs = {"url": [], "domain": [], "ip": [], "email": [],
                "filepath": [], "registry": [r"HKLM\SOFTWARE\Run"]}
        records = make_ioc_records(iocs, "a" * 64)
        reg_recs = [r for r in records if r["type"] == "registry"]
        assert all("persistence" in r["tags"] for r in reg_recs)


# ── sort_ioc_records ──────────────────────────────────────────────────────────

class TestSortIocRecords:
    def test_sorted_by_type_then_normalized(self):
        records = [
            {"type": "url",    "value": "https://z.com", "normalized": "https://z.com"},
            {"type": "domain", "value": "a.com",          "normalized": "a.com"},
            {"type": "ip",     "value": "8.8.8.8",         "normalized": "8.8.8.8"},
            {"type": "domain", "value": "b.com",          "normalized": "b.com"},
            {"type": "url",    "value": "https://a.com", "normalized": "https://a.com"},
        ]
        sorted_recs = sort_ioc_records(records)
        types = [r["type"] for r in sorted_recs]
        # domain comes before ip alphabetically; url comes after
        assert types.index("domain") < types.index("ip")
        assert types.index("ip") < types.index("url")

    def test_stable_within_type(self):
        records = [
            {"type": "domain", "value": "z.com", "normalized": "z.com"},
            {"type": "domain", "value": "a.com", "normalized": "a.com"},
            {"type": "domain", "value": "m.com", "normalized": "m.com"},
        ]
        result = sort_ioc_records(records)
        norms = [r["normalized"] for r in result]
        assert norms == sorted(norms)


# ── deduplicate_ioc_records ───────────────────────────────────────────────────

class TestDeduplicateIOCRecords:
    def test_exact_duplicate_removed(self):
        records = [
            {"type": "domain", "value": "evil.com", "normalized": "evil.com"},
            {"type": "domain", "value": "evil.com", "normalized": "evil.com"},
        ]
        result = deduplicate_ioc_records(records)
        assert len(result) == 1

    def test_case_variant_deduplicated(self):
        # EVIL.COM and evil.com normalize to the same value
        records = [
            {"type": "domain", "value": "EVIL.COM", "normalized": "evil.com"},
            {"type": "domain", "value": "evil.com", "normalized": "evil.com"},
        ]
        result = deduplicate_ioc_records(records)
        assert len(result) == 1
        # First occurrence is kept
        assert result[0]["value"] == "EVIL.COM"

    def test_different_types_not_deduplicated(self):
        records = [
            {"type": "domain", "value": "evil.com", "normalized": "evil.com"},
            {"type": "url",    "value": "evil.com", "normalized": "evil.com"},
        ]
        result = deduplicate_ioc_records(records)
        assert len(result) == 2

    def test_empty_list(self):
        assert deduplicate_ioc_records([]) == []


# ── End-to-end round-trips ────────────────────────────────────────────────────

class TestEndToEnd:
    def test_full_pipeline_on_realistic_text(self):
        sample_text = (
            "C2 at https://evil.ru/gate?id=abc123 "
            "also tries api.evil.ru "
            "exfils to 93.184.216.34:443 "
            "drops C:\\Users\\Public\\svchost32.exe "
            r"adds HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Backdoor "
            "contacts operator@evil.ru"
        )
        iocs = extract_iocs(sample_text)
        assert iocs["url"]      != []
        assert iocs["ip"]       != []
        assert iocs["email"]    != []
        assert iocs["filepath"] != []
        assert iocs["registry"] != []

        records = make_ioc_records(iocs, "a" * 64)
        deduped = deduplicate_ioc_records(records)
        sorted_recs = sort_ioc_records(deduped)

        # Sorted by type first
        prev_type = ""
        prev_norm = ""
        for r in sorted_recs:
            t = r["type"]
            n = r["normalized"]
            assert t >= prev_type, "Types must be sorted"
            if t == prev_type:
                assert n >= prev_norm, "Normalized values must be sorted within type"
            prev_type = t
            prev_norm = n

    def test_deterministic_on_identical_input(self):
        text = "https://c2.evil.com/beacon 8.8.8.8 attacker@evil.com"
        r1 = sort_ioc_records(make_ioc_records(extract_iocs(text), "x" * 64))
        r2 = sort_ioc_records(make_ioc_records(extract_iocs(text), "x" * 64))
        assert r1 == r2

    def test_no_duplicates_after_pipeline(self):
        text = "evil.com evil.com evil.com attacker@evil.com attacker@evil.com"
        iocs = extract_iocs(text)
        records = deduplicate_ioc_records(make_ioc_records(iocs, "a" * 64))
        seen: set[tuple] = set()
        for r in records:
            key = (r["type"], r["normalized"])
            assert key not in seen, f"Duplicate: {key}"
            seen.add(key)
