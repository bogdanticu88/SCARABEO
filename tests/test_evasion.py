"""Unit tests for scarabeo/evasion.py — static evasion heuristics."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from scarabeo.evasion import (
    EvasionIndicator,
    EvasionProfile,
    analyze_imports,
    analyze_strings,
    build_evasion_profile,
    compute_score,
    evasion_profile_to_findings,
)


# ── Fixtures / helpers ────────────────────────────────────────────────────────

def _imp(dll: str, fns: list[str]) -> dict:
    return {"dll": dll, "functions": fns}


def _profile(imports=None, strings=None) -> EvasionProfile:
    return build_evasion_profile(
        imports=imports or [],
        strings=strings or [],
    )


# ── analyze_imports ───────────────────────────────────────────────────────────

class TestAnalyzeImports:
    def test_no_imports_returns_empty(self):
        assert analyze_imports([]) == []

    def test_benign_imports_not_flagged(self):
        imports = [_imp("gdi32.dll", ["CreateDC", "DeleteDC", "BitBlt"])]
        assert analyze_imports(imports) == []

    def test_debugger_presence_detected(self):
        imports = [_imp("kernel32.dll", ["IsDebuggerPresent", "ExitProcess"])]
        indicators = analyze_imports(imports)
        cats = {i.category for i in indicators}
        assert "anti_debug" in cats

    def test_timing_check_detected(self):
        imports = [_imp("kernel32.dll", ["GetTickCount", "QueryPerformanceCounter"])]
        indicators = analyze_imports(imports)
        techniques = {i.technique for i in indicators}
        assert "anti_debug.timing_check" in techniques

    def test_classic_injection_detected(self):
        imports = [_imp("kernel32.dll", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"])]
        indicators = analyze_imports(imports)
        cats = {i.category for i in indicators}
        assert "injection" in cats

    def test_ntdll_native_injection_detected(self):
        imports = [_imp("ntdll.dll", ["NtCreateThreadEx", "NtWriteVirtualMemory"])]
        indicators = analyze_imports(imports)
        techniques = {i.technique for i in indicators}
        assert "injection.nt_thread" in techniques
        assert "injection.nt_memory" in techniques

    def test_process_hollowing_detected(self):
        imports = [
            _imp("ntdll.dll", ["NtUnmapViewOfSection"]),
            _imp("kernel32.dll", ["CreateProcess", "ResumeThread"]),
        ]
        indicators = analyze_imports(imports)
        techniques = {i.technique for i in indicators}
        assert "injection.process_hollowing" in techniques

    def test_token_manipulation_detected(self):
        imports = [_imp("advapi32.dll", ["AdjustTokenPrivileges", "OpenProcessToken"])]
        indicators = analyze_imports(imports)
        cats = {i.category for i in indicators}
        assert "privesc" in cats

    def test_registry_persistence_detected(self):
        imports = [_imp("advapi32.dll", ["RegSetValueExA", "RegCreateKeyA"])]
        indicators = analyze_imports(imports)
        techniques = {i.technique for i in indicators}
        assert "persistence.registry_write" in techniques

    def test_service_installation_detected(self):
        imports = [_imp("advapi32.dll", ["OpenSCManagerA", "CreateServiceA"])]
        indicators = analyze_imports(imports)
        techniques = {i.technique for i in indicators}
        assert "persistence.service_install" in techniques

    def test_network_socket_ops_detected(self):
        imports = [_imp("ws2_32.dll", ["socket", "connect", "send", "recv"])]
        indicators = analyze_imports(imports)
        cats = {i.category for i in indicators}
        assert "network" in cats

    def test_http_client_detected(self):
        imports = [_imp("winhttp.dll", ["WinHttpOpen", "WinHttpConnect"])]
        indicators = analyze_imports(imports)
        cats = {i.category for i in indicators}
        assert "network" in cats

    def test_thread_hiding_detected(self):
        imports = [_imp("ntdll.dll", ["NtSetInformationThread"])]
        indicators = analyze_imports(imports)
        techniques = {i.technique for i in indicators}
        assert "anti_debug.thread_hiding" in techniques

    def test_evidence_contains_matched_functions(self):
        imports = [_imp("kernel32.dll", ["IsDebuggerPresent", "CreateToolhelp32Snapshot"])]
        indicators = analyze_imports(imports)
        all_evidence = {e for ind in indicators for e in ind.evidence}
        assert "IsDebuggerPresent" in all_evidence

    def test_case_sensitivity_dll_name(self):
        # DLL names should match case-insensitively
        imports = [_imp("KERNEL32.DLL", ["IsDebuggerPresent"])]
        indicators = analyze_imports(imports)
        assert any(i.category == "anti_debug" for i in indicators)

    def test_indicator_source_is_imports(self):
        imports = [_imp("ntdll.dll", ["NtCreateThreadEx"])]
        indicators = analyze_imports(imports)
        assert all(i.source == "imports" for i in indicators)

    def test_confidence_at_least_50(self):
        imports = [_imp("kernel32.dll", ["IsDebuggerPresent"])]
        indicators = analyze_imports(imports)
        assert all(i.confidence >= 50 for i in indicators)

    def test_confidence_increases_with_evidence(self):
        # More matched functions → higher confidence
        few = analyze_imports([_imp("kernel32.dll", ["IsDebuggerPresent"])])
        many = analyze_imports([_imp("kernel32.dll", [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "DebugBreak", "OutputDebugStringA",
        ])])
        few_conf  = next((i.confidence for i in few  if i.technique == "anti_debug.debugger_presence"), 0)
        many_conf = next((i.confidence for i in many if i.technique == "anti_debug.debugger_presence"), 0)
        assert many_conf >= few_conf


# ── analyze_strings ───────────────────────────────────────────────────────────

class TestAnalyzeStrings:
    def test_empty_strings_returns_empty(self):
        assert analyze_strings([]) == []

    def test_vm_artifact_detected(self):
        strings = ["vmtoolsd.exe", "normal string", "other"]
        indicators = analyze_strings(strings)
        cats = {i.category for i in indicators}
        assert "anti_vm" in cats

    def test_vbox_artifact_detected(self):
        strings = ["VBoxService.exe running"]
        indicators = analyze_strings(strings)
        assert any("anti_vm" == i.category for i in indicators)

    def test_sandbox_tool_detected(self):
        strings = ["wireshark.exe", "procmon.exe"]
        indicators = analyze_strings(strings)
    	# Both are sandbox artifact strings
        cats = {i.category for i in indicators}
        assert "anti_sandbox" in cats

    def test_cuckoo_detected(self):
        strings = ["cuckoomon.dll loaded at runtime"]
        indicators = analyze_strings(strings)
        assert any("anti_sandbox" == i.category for i in indicators)

    def test_privilege_string_detected(self):
        strings = ["requesting SeDebugPrivilege for process access"]
        indicators = analyze_strings(strings)
        assert any("privesc" == i.category for i in indicators)

    def test_autorun_registry_key_detected(self):
        strings = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"]
        indicators = analyze_strings(strings)
        assert any("persistence" == i.category for i in indicators)

    def test_c2_pattern_detected(self):
        strings = ["executing cmd.exe /c whoami > result.txt"]
        indicators = analyze_strings(strings)
        cats = {i.category for i in indicators}
        assert "network" in cats

    def test_case_insensitive_matching(self):
        # Pattern is "vmtoolsd.exe", input is "VMTOOLSD.EXE"
        strings = ["VMTOOLSD.EXE detected in process list"]
        indicators = analyze_strings(strings)
        assert any("anti_vm" == i.category for i in indicators)

    def test_indicator_source_is_strings(self):
        strings = ["vmtoolsd.exe"]
        indicators = analyze_strings(strings)
        assert all(i.source == "strings" for i in indicators)

    def test_rootkit_strings_detected(self):
        strings = ["opening \\Device\\PhysicalMemory for DKOM"]
        indicators = analyze_strings(strings)
        cats = {i.category for i in indicators}
        assert "stealth" in cats

    def test_benign_strings_not_flagged(self):
        strings = ["Hello World", "error opening file", "version 1.2.3"]
        indicators = analyze_strings(strings)
        assert indicators == []


# ── compute_score ─────────────────────────────────────────────────────────────

class TestComputeScore:
    def test_no_indicators_score_zero(self):
        assert compute_score([]) == 0

    def test_single_low_category_low_score(self):
        inds = [EvasionIndicator(category="network", technique="network.http_client",
                                  source="imports", evidence=["WinHttpOpen"])]
        score = compute_score(inds)
        assert 1 <= score <= 30

    def test_injection_gives_high_score(self):
        inds = [
            EvasionIndicator(category="injection", technique="injection.nt_thread",
                              source="imports", evidence=["NtCreateThreadEx"]),
            EvasionIndicator(category="injection", technique="injection.memory_ops",
                              source="imports", evidence=["VirtualAllocEx"]),
        ]
        score = compute_score(inds)
        assert score >= 25

    def test_score_never_exceeds_100(self):
        # Flood with many indicators across all categories
        inds = [
            EvasionIndicator(category=cat, technique=f"{cat}.x", source="imports", evidence=["x"])
            for cat in ["anti_debug", "anti_vm", "anti_sandbox", "injection",
                        "privesc", "persistence", "network", "stealth"] * 5
        ]
        score = compute_score(inds)
        assert score <= 100

    def test_more_categories_higher_score(self):
        one_cat = [EvasionIndicator(category="anti_debug", technique="t", source="imports", evidence=["x"])]
        two_cat = [
            EvasionIndicator(category="anti_debug", technique="t1", source="imports", evidence=["x"]),
            EvasionIndicator(category="injection",  technique="t2", source="imports", evidence=["y"]),
        ]
        assert compute_score(two_cat) > compute_score(one_cat)


# ── EvasionProfile properties ─────────────────────────────────────────────────

class TestEvasionProfileProperties:
    def test_has_anti_debug_true(self):
        p = _profile(imports=[_imp("kernel32.dll", ["IsDebuggerPresent"])])
        assert p.has_anti_debug is True

    def test_has_anti_debug_false(self):
        p = _profile(imports=[_imp("ws2_32.dll", ["socket"])])
        assert p.has_anti_debug is False

    def test_has_injection_true(self):
        p = _profile(imports=[_imp("kernel32.dll", ["CreateRemoteThread", "VirtualAllocEx"])])
        assert p.has_injection is True

    def test_has_anti_vm_from_strings(self):
        p = _profile(strings=["vmtoolsd.exe running"])
        assert p.has_anti_vm is True

    def test_has_persistence_true(self):
        p = _profile(imports=[_imp("advapi32.dll", ["RegSetValueExA"])])
        assert p.has_persistence is True

    def test_empty_profile_all_false(self):
        p = _profile()
        assert p.score == 0
        assert p.has_anti_debug is False
        assert p.has_injection is False
        assert p.has_anti_vm is False


# ── build_evasion_profile ─────────────────────────────────────────────────────

class TestBuildEvasionProfile:
    def test_combines_import_and_string_indicators(self):
        p = build_evasion_profile(
            imports=[_imp("kernel32.dll", ["IsDebuggerPresent"])],
            strings=["vmtoolsd.exe"],
        )
        cats = {i.category for i in p.indicators}
        assert "anti_debug" in cats
        assert "anti_vm" in cats

    def test_score_is_positive_when_indicators_present(self):
        p = build_evasion_profile(
            imports=[_imp("ntdll.dll", ["NtCreateThreadEx"])],
            strings=[],
        )
        assert p.score > 0

    def test_score_zero_with_no_indicators(self):
        p = build_evasion_profile(imports=[], strings=[])
        assert p.score == 0

    def test_realistic_rat_profile(self):
        """RAT-like import profile should trigger injection + network + persistence."""
        imports = [
            _imp("kernel32.dll", [
                "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                "CreateToolhelp32Snapshot", "Process32First",
            ]),
            _imp("advapi32.dll", ["RegSetValueExA", "AdjustTokenPrivileges"]),
            _imp("ws2_32.dll",   ["socket", "connect", "send", "recv"]),
        ]
        p = build_evasion_profile(imports=imports, strings=[])
        assert p.has_injection
        assert p.has_persistence
        assert p.has_network_c2
        assert p.score >= 30


# ── evasion_profile_to_findings ───────────────────────────────────────────────

class TestEvasionProfileToFindings:
    def test_empty_profile_returns_empty(self):
        p = EvasionProfile(indicators=[], score=0)
        assert evasion_profile_to_findings(p) == []

    def test_findings_have_required_fields(self):
        p = _profile(imports=[_imp("kernel32.dll", ["IsDebuggerPresent"])])
        findings = evasion_profile_to_findings(p)
        required = {"id", "title", "severity", "confidence", "description",
                    "evidence", "source", "created_at"}
        for f in findings:
            missing = required - set(f.keys())
            assert not missing, f"Finding {f.get('id')} missing: {missing}"

    def test_finding_ids_are_stable(self):
        p1 = _profile(imports=[_imp("kernel32.dll", ["IsDebuggerPresent", "VirtualAllocEx"])])
        p2 = _profile(imports=[_imp("kernel32.dll", ["IsDebuggerPresent", "VirtualAllocEx"])])
        ids1 = [f["id"] for f in evasion_profile_to_findings(p1)]
        ids2 = [f["id"] for f in evasion_profile_to_findings(p2)]
        assert ids1 == ids2

    def test_findings_sorted_by_id(self):
        imports = [
            _imp("kernel32.dll", ["IsDebuggerPresent", "VirtualAllocEx", "CreateRemoteThread"]),
            _imp("advapi32.dll", ["AdjustTokenPrivileges", "RegSetValueExA"]),
            _imp("ws2_32.dll", ["socket", "connect"]),
        ]
        p = build_evasion_profile(imports=imports, strings=["vmtoolsd.exe"])
        findings = evasion_profile_to_findings(p)
        ids = [f["id"] for f in findings]
        assert ids == sorted(ids)

    def test_no_duplicate_finding_ids(self):
        imports = [
            _imp("kernel32.dll", ["IsDebuggerPresent", "VirtualAllocEx"]),
            _imp("ntdll.dll", ["NtCreateThreadEx"]),
        ]
        p = _profile(imports=imports)
        findings = evasion_profile_to_findings(p)
        ids = [f["id"] for f in findings]
        assert len(ids) == len(set(ids)), "Finding IDs must be unique"

    def test_severity_injection_is_high(self):
        p = _profile(imports=[_imp("kernel32.dll", ["CreateRemoteThread", "VirtualAllocEx"])])
        findings = evasion_profile_to_findings(p)
        inj = [f for f in findings if "injection" in f["id"]]
        assert inj, "Should have injection finding"
        assert all(f["severity"] == "HIGH" for f in inj)

    def test_evidence_capped_at_ten(self):
        # Lots of matching functions — evidence list should not exceed 10
        fns = [f"Func{i}" for i in range(20)]
        # Manually inject a large indicator
        ind = EvasionIndicator(
            category="injection", technique="injection.memory_ops",
            source="imports", evidence=[f"Func{i}" for i in range(20)]
        )
        p = EvasionProfile(indicators=[ind], score=25)
        findings = evasion_profile_to_findings(p)
        for f in findings:
            assert len(f["evidence"]) <= 10

    def test_source_parameter_used(self):
        p = _profile(imports=[_imp("kernel32.dll", ["IsDebuggerPresent"])])
        findings = evasion_profile_to_findings(p, source="custom-analyzer")
        assert all(f["source"] == "custom-analyzer" for f in findings)

    def test_evasion_tags_present(self):
        p = _profile(imports=[_imp("kernel32.dll", ["IsDebuggerPresent"])])
        findings = evasion_profile_to_findings(p)
        assert all("evasion" in f["tags"] for f in findings)
