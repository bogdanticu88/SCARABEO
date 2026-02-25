"""Unit tests for pe-analyzer.

All tests operate on in-memory PE binaries constructed by _build_pe() and
_build_idata() — no real executables or filesystem access required.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest

# The analyzer imports evasion.py and ioc.py, which are in scarabeo/ but get
# copied into the container at build time.  For tests, put scarabeo/ on the
# path first so those bare-name imports resolve correctly.
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "scarabeo"))
sys.path.insert(0, str(_ROOT / "analyzers" / "pe-analyzer"))
import analyzer as pe  # noqa: E402


# ── PE binary builder ─────────────────────────────────────────────────────────

def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _build_idata(
    dll_imports: dict[str, list[str]],
    section_va: int,
    is_64bit: bool = False,
) -> bytes:
    """
    Build a minimal .idata section blob for the given imports.

    dll_imports: {"kernel32.dll": ["VirtualAlloc", "GetProcAddress"], ...}
    section_va:  virtual address of this section in the image

    Returns raw bytes for the section content. The caller must embed this
    into the PE image at the appropriate file offset, and set the Import
    Directory data directory entry to (section_va, len(result)).

    Layout:
      IID array (N+1 descriptors × 20 bytes, last all-zero)
      INT arrays (N arrays of thunk_size entries, terminated by 0)
      IBN entries (hint WORD + name string + padding)
      DLL name strings
    """
    thunk_size = 8 if is_64bit else 4
    iid_count = len(dll_imports)

    # Pass 1: compute offsets for INT arrays, IBN entries, and DLL names
    # Relative to start of section (0 = section_va)

    iid_table_size = (iid_count + 1) * 20
    int_base = iid_table_size  # INTs follow immediately

    # Build per-dll lists of (fn_name) entries in order
    dlls = list(dll_imports.items())

    # Calculate where each INT starts
    int_offsets: list[int] = []
    cursor = int_base
    for _dll_name, fns in dlls:
        int_offsets.append(cursor)
        cursor += (len(fns) + 1) * thunk_size  # +1 for terminating null thunk

    ibn_base = cursor

    # Calculate where each IBN entry starts (for each function)
    ibn_offsets: list[list[int]] = []
    for _dll_name, fns in dlls:
        fn_offsets: list[int] = []
        for fn in fns:
            fn_offsets.append(cursor)
            # WORD hint (2) + name + null
            cursor += 2 + len(fn) + 1
            if cursor % 2:  # word-align
                cursor += 1
        ibn_offsets.append(fn_offsets)

    dll_name_base = cursor
    dll_name_offsets: list[int] = []
    for dll_name, _ in dlls:
        dll_name_offsets.append(cursor)
        cursor += len(dll_name) + 1

    total_size = cursor

    buf = bytearray(total_size)

    # Write IIDs
    for i, (dll_name, fns) in enumerate(dlls):
        iid_off = i * 20
        int_rva = section_va + int_offsets[i]
        name_rva = section_va + dll_name_offsets[i]
        struct.pack_into("<I", buf, iid_off + 0, int_rva)    # OriginalFirstThunk (INT)
        struct.pack_into("<I", buf, iid_off + 4, 0)          # TimeDateStamp
        struct.pack_into("<I", buf, iid_off + 8, 0)          # ForwarderChain
        struct.pack_into("<I", buf, iid_off + 12, name_rva)  # Name
        struct.pack_into("<I", buf, iid_off + 16, 0)         # FirstThunk (IAT — zero here)

    # Terminating zero IID
    # (buf is already zeroed, so no action needed)

    # Write INT thunks and IBN entries
    for i, (dll_name, fns) in enumerate(dlls):
        int_off = int_offsets[i]
        for j, fn in enumerate(fns):
            ibn_rva = section_va + ibn_offsets[i][j]
            if is_64bit:
                struct.pack_into("<Q", buf, int_off + j * thunk_size, ibn_rva)
            else:
                struct.pack_into("<I", buf, int_off + j * thunk_size, ibn_rva)
            # Write IBN: WORD hint=0 + function name
            ibn_off = ibn_offsets[i][j]
            struct.pack_into("<H", buf, ibn_off, 0)  # hint
            name_bytes = fn.encode("ascii") + b"\x00"
            buf[ibn_off + 2: ibn_off + 2 + len(name_bytes)] = name_bytes
        # Terminating null thunk already zeroed

    # Write DLL names
    for i, (dll_name, _) in enumerate(dlls):
        off = dll_name_offsets[i]
        name_bytes = dll_name.encode("ascii") + b"\x00"
        buf[off: off + len(name_bytes)] = name_bytes

    return bytes(buf)


def _build_pe(
    machine: int = 0x14c,       # i386
    timestamp: int = 0x5E000000,
    subsystem: int = 3,          # CUI
    sections: list[dict] | None = None,
    dll_imports: dict[str, list[str]] | None = None,
    is_64bit: bool = False,
) -> bytes:
    """
    Build a minimal but structurally valid PE file in memory.

    sections: list of dicts with keys:
        name (str, ≤8 chars), characteristics (int), data (bytes)
    dll_imports: {"dll.dll": ["Fn1", "Fn2"]}

    Returns raw PE bytes.
    """
    if sections is None:
        sections = []
    if dll_imports is None:
        dll_imports = {}

    FILE_ALIGN  = 0x200
    SECT_ALIGN  = 0x1000
    OPT_MAGIC   = 0x20B if is_64bit else 0x10B

    # ── Geometry: fixed headers ────────────────────────────────────────────
    DOS_SIZE        = 0x40
    PE_SIG_SIZE     = 4
    COFF_SIZE       = 20
    OPT_SIZE        = 240 if is_64bit else 224
    SECT_HDR_SIZE   = 40

    e_lfanew        = DOS_SIZE
    coff_off        = e_lfanew + PE_SIG_SIZE
    opt_off         = coff_off + COFF_SIZE
    sect_table_off  = opt_off + OPT_SIZE

    # If we have imports to add, synthesise a .idata section
    idata_bytes = b""
    if dll_imports:
        # Placeholder section VA — will be resolved in the section layout loop
        # We'll add .idata as the first section for simplicity
        sections = list(sections)  # copy
        sections.insert(0, {"name": ".idata", "characteristics": 0xC0000040, "data": b"\x00"})

    n_sections = len(sections)
    headers_raw_size = _align(sect_table_off + n_sections * SECT_HDR_SIZE, FILE_ALIGN)

    # ── Assign VAs and file offsets to each section ───────────────────────
    image_va = 0x1000       # first section VA
    file_off = headers_raw_size
    section_layouts: list[dict] = []

    for sec in sections:
        raw_data = sec.get("data", b"")
        virt_size = len(raw_data) if raw_data else SECT_ALIGN
        raw_size  = _align(len(raw_data), FILE_ALIGN) if raw_data else 0

        section_layouts.append({
            "name":             sec["name"],
            "characteristics":  sec["characteristics"],
            "virtual_address":  image_va,
            "virtual_size":     virt_size,
            "raw_offset":       file_off,
            "raw_size":         raw_size,
            "raw_data":         raw_data,
        })

        image_va = _align(image_va + virt_size, SECT_ALIGN)
        file_off += raw_size

    # Compute .idata bytes now that we know the VA
    import_dir_rva = 0
    import_dir_size = 0
    if dll_imports:
        idata_layout = section_layouts[0]  # we inserted .idata first
        idata_bytes = _build_idata(dll_imports, idata_layout["virtual_address"], is_64bit)
        idata_layout["raw_data"]    = idata_bytes
        idata_layout["virtual_size"] = len(idata_bytes)
        idata_layout["raw_size"]    = _align(len(idata_bytes), FILE_ALIGN)
        import_dir_rva  = idata_layout["virtual_address"]
        import_dir_size = len(idata_bytes)

        # Recalculate file offsets after .idata size is known
        file_off = headers_raw_size
        for sl in section_layouts:
            sl["raw_offset"] = file_off
            file_off += sl["raw_size"]

    image_size = _align(image_va, SECT_ALIGN)
    total_size = file_off

    buf = bytearray(total_size)

    # ── DOS header ─────────────────────────────────────────────────────────
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)

    # ── PE signature ───────────────────────────────────────────────────────
    buf[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"

    # ── COFF header ────────────────────────────────────────────────────────
    machine_val = 0x8664 if is_64bit else machine
    struct.pack_into("<H", buf, coff_off + 0,  machine_val)
    struct.pack_into("<H", buf, coff_off + 2,  n_sections)
    struct.pack_into("<I", buf, coff_off + 4,  timestamp)
    struct.pack_into("<I", buf, coff_off + 8,  0)   # PointerToSymbolTable
    struct.pack_into("<I", buf, coff_off + 12, 0)   # NumberOfSymbols
    struct.pack_into("<H", buf, coff_off + 16, OPT_SIZE)
    struct.pack_into("<H", buf, coff_off + 18, 0x0002)  # IMAGE_FILE_EXECUTABLE_IMAGE

    # ── Optional header ────────────────────────────────────────────────────
    struct.pack_into("<H", buf, opt_off + 0,  OPT_MAGIC)
    struct.pack_into("<B", buf, opt_off + 2,  14)   # MajorLinkerVersion
    struct.pack_into("<B", buf, opt_off + 3,  0)
    # SizeOfCode / SizeOfInitializedData / SizeOfUninitializedData
    struct.pack_into("<I", buf, opt_off + 4,  0)
    struct.pack_into("<I", buf, opt_off + 8,  0)
    struct.pack_into("<I", buf, opt_off + 12, 0)
    # AddressOfEntryPoint
    struct.pack_into("<I", buf, opt_off + 16, 0x1000)

    if is_64bit:
        struct.pack_into("<Q", buf, opt_off + 24, 0x140000000)  # ImageBase
        struct.pack_into("<I", buf, opt_off + 32, SECT_ALIGN)   # SectionAlignment
        struct.pack_into("<I", buf, opt_off + 36, FILE_ALIGN)   # FileAlignment
        struct.pack_into("<I", buf, opt_off + 56, image_size)   # SizeOfImage
        struct.pack_into("<I", buf, opt_off + 60, headers_raw_size)  # SizeOfHeaders
        struct.pack_into("<H", buf, opt_off + 68, subsystem)
        # Data directories start at offset 112 (for PE32+)
        # [1] Import Directory
        struct.pack_into("<I", buf, opt_off + 120, import_dir_rva)
        struct.pack_into("<I", buf, opt_off + 124, import_dir_size)
    else:
        struct.pack_into("<I", buf, opt_off + 28, 0x00400000)   # ImageBase
        struct.pack_into("<I", buf, opt_off + 32, SECT_ALIGN)
        struct.pack_into("<I", buf, opt_off + 36, FILE_ALIGN)
        struct.pack_into("<I", buf, opt_off + 56, image_size)
        struct.pack_into("<I", buf, opt_off + 60, headers_raw_size)
        struct.pack_into("<H", buf, opt_off + 68, subsystem)
        # Data directories start at offset 96 (for PE32)
        # [1] Import Directory
        struct.pack_into("<I", buf, opt_off + 104, import_dir_rva)
        struct.pack_into("<I", buf, opt_off + 108, import_dir_size)

    # ── Section headers ────────────────────────────────────────────────────
    for i, sl in enumerate(section_layouts):
        off = sect_table_off + i * SECT_HDR_SIZE
        name_bytes = sl["name"].encode("ascii", errors="replace")[:8].ljust(8, b"\x00")
        buf[off:off + 8] = name_bytes
        struct.pack_into("<I", buf, off + 8,  sl["virtual_size"])
        struct.pack_into("<I", buf, off + 12, sl["virtual_address"])
        struct.pack_into("<I", buf, off + 16, sl["raw_size"])
        struct.pack_into("<I", buf, off + 20, sl["raw_offset"])
        struct.pack_into("<I", buf, off + 36, sl["characteristics"])

    # ── Section data ───────────────────────────────────────────────────────
    for sl in section_layouts:
        raw = sl["raw_data"]
        if raw:
            buf[sl["raw_offset"]: sl["raw_offset"] + len(raw)] = raw

    return bytes(buf)


# ── Helper ────────────────────────────────────────────────────────────────────

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Tests: DOS / PE header parsing ───────────────────────────────────────────

class TestParseDosHeader:
    def test_valid_mz(self):
        pe_bytes = _build_pe()
        result = pe.parse_dos_header(pe_bytes)
        assert result is not None
        assert result["e_lfanew"] == 0x40

    def test_too_short(self):
        assert pe.parse_dos_header(b"MZ") is None

    def test_wrong_magic(self):
        data = bytearray(_build_pe())
        data[0:2] = b"ZM"
        assert pe.parse_dos_header(bytes(data)) is None


class TestParsePeHeader:
    def test_basic_pe32(self):
        pe_bytes = _build_pe(machine=0x14c, subsystem=3)
        dos = pe.parse_dos_header(pe_bytes)
        header = pe.parse_pe_header(pe_bytes, dos)
        assert header is not None
        assert header["is_pe32_plus"] is False
        assert header["machine"] == "i386"
        assert header["subsystem"] == "Windows CUI"
        assert header["subsystem_code"] == 3

    def test_pe32_plus(self):
        pe_bytes = _build_pe(is_64bit=True, subsystem=3)
        dos = pe.parse_dos_header(pe_bytes)
        header = pe.parse_pe_header(pe_bytes, dos)
        assert header is not None
        assert header["is_pe32_plus"] is True
        assert header["machine"] == "AMD64"

    def test_wrong_pe_signature(self):
        data = bytearray(_build_pe())
        data[0x40:0x44] = b"XX\x00\x00"
        dos = pe.parse_dos_header(bytes(data))
        assert pe.parse_pe_header(bytes(data), dos) is None


# ── Tests: section parsing ────────────────────────────────────────────────────

class TestParseSections:
    def test_section_names_and_count(self):
        pe_bytes = _build_pe(sections=[
            {"name": ".text", "characteristics": 0x60000020, "data": b"\x90" * 256},
            {"name": ".data", "characteristics": 0xC0000040, "data": b"\x00" * 128},
        ])
        dos = pe.parse_dos_header(pe_bytes)
        hdr = pe.parse_pe_header(pe_bytes, dos)
        sections = pe.parse_sections(pe_bytes, hdr)
        assert len(sections) == 2
        assert sections[0]["name"] == ".text"
        assert sections[1]["name"] == ".data"

    def test_section_entropy_computed(self):
        # High-entropy section: random-like bytes
        high_ent_data = bytes(range(256)) * 4  # all byte values equally — max entropy
        pe_bytes = _build_pe(sections=[
            {"name": ".packed", "characteristics": 0xE0000020, "data": high_ent_data},
        ])
        dos = pe.parse_dos_header(pe_bytes)
        hdr = pe.parse_pe_header(pe_bytes, dos)
        sections = pe.parse_sections(pe_bytes, hdr)
        assert sections[0]["entropy"] == 8.0

    def test_zero_raw_size_entropy_zero(self):
        # Section with raw_size=0 (common for BSS-like sections)
        pe_bytes = _build_pe(sections=[
            {"name": ".bss", "characteristics": 0xC0000000, "data": b""},
        ])
        dos = pe.parse_dos_header(pe_bytes)
        hdr = pe.parse_pe_header(pe_bytes, dos)
        sections = pe.parse_sections(pe_bytes, hdr)
        assert sections[0]["entropy"] == 0.0


# ── Tests: import parsing ─────────────────────────────────────────────────────

class TestParseImportDirectory:
    def test_no_imports(self):
        pe_bytes = _build_pe()
        dos = pe.parse_dos_header(pe_bytes)
        hdr = pe.parse_pe_header(pe_bytes, dos)
        sects = pe.parse_sections(pe_bytes, hdr)
        result = pe.parse_import_directory(pe_bytes, hdr, sects)
        assert result == []

    def test_single_dll_import(self):
        pe_bytes = _build_pe(dll_imports={"kernel32.dll": ["VirtualAlloc", "GetProcAddress"]})
        dos = pe.parse_dos_header(pe_bytes)
        hdr = pe.parse_pe_header(pe_bytes, dos)
        sects = pe.parse_sections(pe_bytes, hdr)
        imports = pe.parse_import_directory(pe_bytes, hdr, sects)
        assert len(imports) == 1
        assert imports[0]["dll"] == "kernel32.dll"
        assert "VirtualAlloc" in imports[0]["functions"]
        assert "GetProcAddress" in imports[0]["functions"]

    def test_multiple_dlls(self):
        pe_bytes = _build_pe(dll_imports={
            "kernel32.dll": ["VirtualAlloc"],
            "ws2_32.dll":   ["connect", "send"],
        })
        dos = pe.parse_dos_header(pe_bytes)
        hdr = pe.parse_pe_header(pe_bytes, dos)
        sects = pe.parse_sections(pe_bytes, hdr)
        imports = pe.parse_import_directory(pe_bytes, hdr, sects)
        dll_names = {imp["dll"] for imp in imports}
        assert "kernel32.dll" in dll_names
        assert "ws2_32.dll" in dll_names

    def test_pe32_plus_imports(self):
        pe_bytes = _build_pe(
            is_64bit=True,
            dll_imports={"ntdll.dll": ["NtCreateThreadEx"]},
        )
        dos = pe.parse_dos_header(pe_bytes)
        hdr = pe.parse_pe_header(pe_bytes, dos)
        sects = pe.parse_sections(pe_bytes, hdr)
        imports = pe.parse_import_directory(pe_bytes, hdr, sects)
        assert any(imp["dll"] == "ntdll.dll" for imp in imports)
        ntdll = next(imp for imp in imports if imp["dll"] == "ntdll.dll")
        assert "NtCreateThreadEx" in ntdll["functions"]


# ── Tests: packer detection ───────────────────────────────────────────────────

class TestDetectPacker:
    def test_upx_detected(self):
        sections = [
            {"name": "UPX0", "characteristics": 0, "entropy": 0.0,
             "virtual_size": 0, "virtual_address": 0, "raw_size": 0, "raw_offset": 0},
            {"name": "UPX1", "characteristics": 0, "entropy": 7.9,
             "virtual_size": 8192, "virtual_address": 0x1000, "raw_size": 8192, "raw_offset": 0x200},
        ]
        assert pe.detect_packer(sections) == ["upx"]

    def test_no_packer(self):
        sections = [
            {"name": ".text", "characteristics": 0, "entropy": 3.0,
             "virtual_size": 4096, "virtual_address": 0x1000, "raw_size": 4096, "raw_offset": 0x200},
        ]
        assert pe.detect_packer(sections) == []

    def test_vmprotect_detected(self):
        sections = [
            {"name": ".vmp0", "characteristics": 0, "entropy": 7.5,
             "virtual_size": 4096, "virtual_address": 0x1000, "raw_size": 4096, "raw_offset": 0x200},
        ]
        assert pe.detect_packer(sections) == ["vmprotect"]


# ── Tests: section anomaly detection ─────────────────────────────────────────

class TestDetectSectionAnomalies:
    def test_rwx_detected(self):
        sections = [{
            "name": ".bad",
            "characteristics": pe.SCN_MEM_EXECUTE | pe.SCN_MEM_READ | pe.SCN_MEM_WRITE,
            "virtual_size": 4096,
            "raw_size": 4096,
            "virtual_address": 0x1000,
            "raw_offset": 0x200,
            "entropy": 0.0,
        }]
        anomalies = pe.detect_section_anomalies(sections)
        assert any(a["type"] == "rwx" for a in anomalies)

    def test_vsize_inflation_detected(self):
        sections = [{
            "name": ".unpack",
            "characteristics": pe.SCN_MEM_READ | pe.SCN_MEM_WRITE,
            "virtual_size": 65536,   # >> raw_size * 4
            "raw_size": 512,
            "virtual_address": 0x1000,
            "raw_offset": 0x200,
            "entropy": 0.0,
        }]
        anomalies = pe.detect_section_anomalies(sections)
        assert any(a["type"] == "vsize_inflation" for a in anomalies)

    def test_normal_section_no_anomalies(self):
        sections = [{
            "name": ".text",
            "characteristics": pe.SCN_MEM_EXECUTE | pe.SCN_MEM_READ,  # no write
            "virtual_size": 4096,
            "raw_size": 4096,
            "virtual_address": 0x1000,
            "raw_offset": 0x200,
            "entropy": 3.5,
        }]
        assert pe.detect_section_anomalies(sections) == []


# ── Tests: suspicious import detection ───────────────────────────────────────

class TestDetectSuspiciousImports:
    def test_suspicious_kernel32(self):
        imports = [{"dll": "kernel32.dll", "functions": ["VirtualAlloc", "GetProcAddress", "CreateFile"]}]
        hits = pe.detect_suspicious_imports(imports)
        assert len(hits) == 1
        assert hits[0]["dll"] == "kernel32.dll"
        assert "VirtualAlloc" in hits[0]["functions"]
        assert "GetProcAddress" in hits[0]["functions"]

    def test_benign_dll_not_flagged(self):
        imports = [{"dll": "gdi32.dll", "functions": ["CreateCompatibleDC"]}]
        hits = pe.detect_suspicious_imports(imports)
        assert hits == []

    def test_ws2_32_network(self):
        imports = [{"dll": "ws2_32.dll", "functions": ["connect", "send", "recv"]}]
        hits = pe.detect_suspicious_imports(imports)
        assert len(hits) == 1
        assert "connect" in hits[0]["functions"]

    def test_case_insensitive_dll(self):
        imports = [{"dll": "KERNEL32.DLL", "functions": ["VirtualAlloc"]}]
        hits = pe.detect_suspicious_imports(imports)
        assert len(hits) == 1


# ── Tests: finding generation ─────────────────────────────────────────────────

class TestGenerateFindings:
    def _minimal_pe_header(self, subsystem_code=3, timestamp=0x5E000000):
        return {
            "subsystem_code": subsystem_code,
            "timestamp": timestamp,
            "machine": "i386",
        }

    def test_packer_finding_stable_id(self):
        sections = [
            {"name": "UPX0", "characteristics": 0, "entropy": 0.0,
             "virtual_size": 0, "virtual_address": 0x1000, "raw_size": 0, "raw_offset": 0},
            {"name": "UPX1", "characteristics": 0, "entropy": 7.9,
             "virtual_size": 4096, "virtual_address": 0x2000, "raw_size": 4096, "raw_offset": 0x200},
        ]
        packers = pe.detect_packer(sections)
        findings = pe.generate_findings(
            self._minimal_pe_header(), sections, [], packers, None, [], []
        )
        ids = [f["id"] for f in findings]
        assert "pe-packer-upx" in ids
        assert "pe-entropy-sections" in ids

    def test_timestamp_zero_finding(self):
        hdr = self._minimal_pe_header(timestamp=0)
        anomaly = pe.check_timestamp_anomaly(hdr)
        findings = pe.generate_findings(hdr, [], [], [], anomaly, [], [])
        ids = [f["id"] for f in findings]
        assert "pe-timestamp-zero_timestamp" in ids

    def test_gui_no_rsrc_finding(self):
        findings = pe.generate_findings(
            self._minimal_pe_header(subsystem_code=2), [], [], [], None, [], []
        )
        ids = [f["id"] for f in findings]
        assert "pe-gui-no-resources" in ids

    def test_gui_with_rsrc_no_finding(self):
        sections = [{"name": ".rsrc", "characteristics": 0, "entropy": 1.0,
                     "virtual_size": 512, "virtual_address": 0x1000, "raw_size": 512, "raw_offset": 0x200}]
        findings = pe.generate_findings(
            self._minimal_pe_header(subsystem_code=2), sections, [], [], None, [], []
        )
        ids = [f["id"] for f in findings]
        assert "pe-gui-no-resources" not in ids

    def test_rwx_section_finding(self):
        anomalies = [{"section": ".bad", "type": "rwx",
                      "detail": "section '.bad' is readable, writable, and executable"}]
        findings = pe.generate_findings(
            self._minimal_pe_header(), [], [], [], None, anomalies, []
        )
        ids = [f["id"] for f in findings]
        assert "pe-section-rwx-bad" in ids

    def test_findings_sorted_by_id(self):
        sections = [
            {"name": "UPX0", "characteristics": 0, "entropy": 0.0,
             "virtual_size": 0, "virtual_address": 0x1000, "raw_size": 0, "raw_offset": 0},
        ]
        packers = ["upx"]
        anomalies = [{"section": ".bad", "type": "rwx",
                      "detail": "section '.bad' is readable, writable, and executable"}]
        findings = pe.generate_findings(
            self._minimal_pe_header(subsystem_code=2, timestamp=0),
            sections, [], packers, None, anomalies, []
        )
        ids = [f["id"] for f in findings]
        assert ids == sorted(ids), "Findings must be sorted by id"

    def test_no_duplicate_ids(self):
        sections = [
            {"name": "UPX0", "characteristics": 0, "entropy": 0.0,
             "virtual_size": 0, "virtual_address": 0x1000, "raw_size": 0, "raw_offset": 0},
            {"name": "UPX1", "characteristics": 0, "entropy": 7.9,
             "virtual_size": 4096, "virtual_address": 0x2000, "raw_size": 4096, "raw_offset": 0x200},
        ]
        findings = pe.generate_findings(
            self._minimal_pe_header(), sections, [], ["upx"], None, [], []
        )
        ids = [f["id"] for f in findings]
        assert len(ids) == len(set(ids)), "Finding IDs must be unique"


# ── Tests: analyze_pe_bytes (integration) ─────────────────────────────────────

class TestAnalyzePeBytes:
    def test_basic_pe_returns_partial_schema(self):
        pe_bytes = _build_pe()
        result = pe.analyze_pe_bytes(pe_bytes, sha256(pe_bytes))
        assert result["schema_version"] == "1.0.0"
        assert result["analyzer_name"] == "pe-analyzer"
        assert isinstance(result["findings"], list)
        assert isinstance(result["iocs"], list)
        assert isinstance(result["artifacts"], list)

    def test_artifacts_have_sha256(self):
        pe_bytes = _build_pe()
        result = pe.analyze_pe_bytes(pe_bytes, sha256(pe_bytes))
        for artifact in result["artifacts"]:
            assert "sha256" in artifact
            assert len(artifact["sha256"]) == 64

    def test_invalid_magic_raises(self):
        with pytest.raises(ValueError, match="DOS header"):
            pe.analyze_pe_bytes(b"\x00" * 512, "a" * 64)

    def test_upx_packed_pe(self):
        high_ent_data = bytes(range(256)) * 32
        pe_bytes = _build_pe(sections=[
            {"name": "UPX0", "characteristics": 0xE0000020, "data": b""},
            {"name": "UPX1", "characteristics": 0xE0000020, "data": high_ent_data},
        ])
        result = pe.analyze_pe_bytes(pe_bytes, sha256(pe_bytes))
        finding_ids = [f["id"] for f in result["findings"]]
        assert "pe-packer-upx" in finding_ids
        assert "pe-entropy-sections" in finding_ids

    def test_suspicious_imports_finding(self):
        pe_bytes = _build_pe(dll_imports={
            "kernel32.dll": ["VirtualAlloc", "WriteProcessMemory"],
        })
        result = pe.analyze_pe_bytes(pe_bytes, sha256(pe_bytes))
        finding_ids = [f["id"] for f in result["findings"]]
        assert any("pe-imports-suspicious" in fid for fid in finding_ids)

    def test_deterministic_output(self):
        pe_bytes = _build_pe(dll_imports={
            "kernel32.dll": ["VirtualAlloc"],
            "ws2_32.dll":   ["connect"],
        })
        h = sha256(pe_bytes)
        result1 = pe.analyze_pe_bytes(pe_bytes, h)
        result2 = pe.analyze_pe_bytes(pe_bytes, h)
        # Strip created_at timestamps before comparing
        def strip_ts(r):
            import copy
            r2 = copy.deepcopy(r)
            for f in r2.get("findings", []):
                f.pop("created_at", None)
            return r2

        assert strip_ts(result1) == strip_ts(result2)

    def test_metadata_contains_pe_fields(self):
        pe_bytes = _build_pe(machine=0x14c, subsystem=2)
        result = pe.analyze_pe_bytes(pe_bytes, sha256(pe_bytes))
        meta = result["metadata"]
        assert meta["file_type"] == "pe"
        assert "sections" in meta
        assert "imports" in meta
        assert "machine" in meta

    def test_imports_artifact_content(self):
        pe_bytes = _build_pe(dll_imports={"ws2_32.dll": ["connect", "send"]})
        result = pe.analyze_pe_bytes(pe_bytes, sha256(pe_bytes))
        artifact_types = [a["type"] for a in result["artifacts"]]
        assert "imports" in artifact_types
        assert "pe_summary" in artifact_types


# ── Tests: fixture round-trip ─────────────────────────────────────────────────

class TestFixture:
    """Sanity-check the reference fixture against the partial schema contract."""

    def test_fixture_schema_fields(self):
        fixture_path = Path(__file__).parent / "fixtures" / "pe_analyzer_output.json"
        with open(fixture_path) as f:
            data = json.load(f)

        assert data["schema_version"] == "1.0.0"
        assert data["analyzer_name"] == "pe-analyzer"
        assert isinstance(data["findings"], list)
        assert isinstance(data["iocs"], list)
        assert isinstance(data["artifacts"], list)

    def test_fixture_findings_have_required_fields(self):
        fixture_path = Path(__file__).parent / "fixtures" / "pe_analyzer_output.json"
        with open(fixture_path) as f:
            data = json.load(f)

        required = {"id", "title", "severity", "confidence", "description", "source", "created_at"}
        for finding in data["findings"]:
            missing = required - set(finding.keys())
            assert not missing, f"Finding {finding.get('id')} missing: {missing}"
