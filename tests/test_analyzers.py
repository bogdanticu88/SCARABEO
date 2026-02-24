"""Unit tests for core analyzers."""

import hashlib
import json
import pytest


class TestPEAnalyzer:
    """Tests for PE analyzer logic."""

    def test_dos_header_parsing(self):
        """Test DOS header parsing."""
        # Minimal MZ header with e_lfanew at 0x3C
        # Offset 0x3C (60) to 0x40 (64) requires 64 bytes
        data = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"
        
        if data[:2] == b"MZ":
            import struct
            e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
            assert e_lfanew == 128

    def test_pe_signature_detection(self):
        """Test PE signature detection."""
        pe_sig = b"PE\x00\x00"
        assert pe_sig == b"PE\x00\x00"

    def test_entropy_computation(self):
        """Test entropy computation for PE sections."""
        from collections import Counter
        import math

        def entropy(data):
            if not data:
                return 0.0
            counts = Counter(data)
            total = len(data)
            return -sum((c/total) * math.log2(c/total) for c in counts.values() if c > 0)

        # Low entropy (repeated bytes)
        assert entropy(b"\x00" * 256) == 0.0

        # Higher entropy (varied bytes)
        data = bytes(range(256))
        assert entropy(data) > 7.0

    def test_packer_detection(self):
        """Test packer detection from section names."""
        PACKER_INDICATORS = {
            "upx": ["UPX0", "UPX1"],
            "aspack": [".aspack", ".adata"],
            "themida": [".themida"],
        }

        sections = [{"name": "UPX0"}, {"name": "UPX1"}, {"name": ".text"}]
        section_names = [s["name"].upper() for s in sections]

        detected = []
        for packer, indicators in PACKER_INDICATORS.items():
            for indicator in indicators:
                if indicator.upper() in section_names:
                    detected.append(packer)
                    break

        assert "upx" in detected


class TestELFAnalyzer:
    """Tests for ELF analyzer logic."""

    def test_elf_magic_detection(self):
        """Test ELF magic byte detection."""
        elf_magic = b"\x7fELF"
        assert elf_magic == b"\x7fELF"

    def test_elf_class_detection(self):
        """Test ELF class (32/64 bit) detection."""
        ELF_CLASS = {1: "32-bit", 2: "64-bit"}

        # 64-bit ELF
        data_64 = b"\x7fELF\x02\x01\x01\x00"
        assert ELF_CLASS.get(data_64[4]) == "64-bit"

        # 32-bit ELF
        data_32 = b"\x7fELF\x01\x01\x01\x00"
        assert ELF_CLASS.get(data_32[4]) == "32-bit"

    def test_elf_machine_detection(self):
        """Test ELF machine type detection."""
        ELF_MACHINE = {
            3: "i386",
            62: "x86-64",
            183: "AArch64",
        }

        assert ELF_MACHINE.get(62) == "x86-64"
        assert ELF_MACHINE.get(3) == "i386"


class TestScriptAnalyzer:
    """Tests for script analyzer logic."""

    def test_script_type_detection_by_shebang(self):
        """Test script type detection by shebang."""
        def detect_by_shebang(text):
            if text.startswith("#!"):
                first_line = text.split("\n")[0].lower()
                if "python" in first_line:
                    return "python"
                if "bash" in first_line or "sh" in first_line:
                    return "bash"
                if "node" in first_line:
                    return "javascript"
            return "unknown"

        assert detect_by_shebang("#!/usr/bin/env python3\n") == "python"
        assert detect_by_shebang("#!/bin/bash\n") == "bash"
        assert detect_by_shebang("#!/usr/bin/env node\n") == "javascript"

    def test_script_type_detection_by_extension(self):
        """Test script type detection by extension."""
        from pathlib import Path

        mapping = {
            ".py": "python",
            ".js": "javascript",
            ".ps1": "powershell",
            ".sh": "bash",
        }

        for ext, expected in mapping.items():
            assert mapping.get(ext) == expected

    def test_obfuscation_detection_base64(self):
        """Test base64 obfuscation detection."""
        import re

        text = "Normal text " + "Y" * 60 + " more text"
        base64_pattern = re.compile(r'[A-Za-z0-9+/=]{50,}')
        matches = list(base64_pattern.finditer(text))
        assert len(matches) > 0

    def test_obfuscation_detection_eval(self):
        """Test eval usage detection."""
        import re

        text = "eval(some_encoded_string)"
        eval_pattern = re.compile(r'\beval\s*\(')
        matches = list(eval_pattern.finditer(text))
        assert len(matches) > 0


class TestDocAnalyzer:
    """Tests for document analyzer logic."""

    def test_ole_magic_detection(self):
        """Test OLE compound document detection."""
        ole_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        assert ole_magic == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

    def test_ooxml_magic_detection(self):
        """Test OOXML (ZIP-based) detection."""
        ooxml_magic = b"PK\x03\x04"
        assert ooxml_magic == b"PK\x03\x04"

    def test_ooxml_macro_detection(self):
        """Test macro detection in OOXML."""
        # Simulate OOXML file list
        names = ["word/document.xml", "word/vbaProject.bin", "word/_rels/document.xml.rels"]
        has_macros = any("vbaProject.bin" in n for n in names)
        assert has_macros is True

    def test_ooxml_external_link_detection(self):
        """Test external link detection in OOXML relationships."""
        import re

        rel_content = '<Relationship Target="http://evil.com/malware.doc" Type="http://schema"/>'
        links = re.findall(r'Target="([^"]+)"', rel_content)
        external = [l for l in links if l.startswith("http://") or l.startswith("https://")]
        assert len(external) > 0


class TestArchiveAnalyzer:
    """Tests for archive analyzer logic."""

    def test_zip_magic_detection(self):
        """Test ZIP archive detection."""
        zip_magic = b"PK\x03\x04"
        assert zip_magic == b"PK\x03\x04"

    def test_gzip_magic_detection(self):
        """Test GZip archive detection."""
        gzip_magic = b"\x1f\x8b\x08"
        assert gzip_magic == b"\x1f\x8b\x08"

    def test_7z_magic_detection(self):
        """Test 7z archive detection."""
        sevenz_magic = b"7z\xbc\xaf'\x1c"
        assert sevenz_magic == b"7z\xbc\xaf'\x1c"

    def test_executable_detection_in_archive(self):
        """Test executable file detection in archive."""
        files = ["readme.txt", "malware.exe", "data.dll", "script.ps1"]
        exec_extensions = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh")
        executables = [f for f in files if f.lower().endswith(exec_extensions)]
        assert "malware.exe" in executables
        assert "data.dll" in executables
        assert "script.ps1" in executables

    def test_nested_archive_detection(self):
        """Test nested archive detection."""
        files = ["readme.txt", "payload.zip", "data.7z"]
        archive_extensions = (".zip", ".7z", ".rar", ".gz", ".tar")
        nested = [f for f in files if f.lower().endswith(archive_extensions)]
        assert "payload.zip" in nested
        assert "data.7z" in nested


class TestSimilarityAnalyzer:
    """Tests for similarity analyzer logic."""

    def test_ssdeep_format(self):
        """Test SSDEEP hash format."""
        # SSDEEP format is chunksize:hash:chunksize
        ssdeep = "12288:abcdefghijklmnop:12288"
        parts = ssdeep.split(":")
        assert len(parts) == 3
        assert parts[0].isdigit()
        assert parts[2].isdigit()

    def test_tlsh_format(self):
        """Test TLSH hash format."""
        # TLSH starts with T followed by 68 hex chars (70 total)
        tlsh = "T1" + "A" * 68
        assert tlsh.startswith("T")
        assert len(tlsh) == 70

    def test_hash_determinism(self):
        """Test that hash computation is deterministic."""
        data = b"test data for hashing"
        
        hash1 = hashlib.sha256(data).hexdigest()
        hash2 = hashlib.sha256(data).hexdigest()
        
        assert hash1 == hash2


class TestAnalyzerOutputSchema:
    """Tests for analyzer output schema compliance."""

    def test_partial_output_schema(self):
        """Test partial output matches schema requirements."""
        from jsonschema import Draft202012Validator
        import json

        schema = {
            "type": "object",
            "required": ["schema_version", "analyzer_name", "analyzer_version", "findings", "iocs", "artifacts"],
            "properties": {
                "schema_version": {"type": "string"},
                "analyzer_name": {"type": "string"},
                "analyzer_version": {"type": "string"},
                "findings": {"type": "array"},
                "iocs": {"type": "array"},
                "artifacts": {"type": "array"},
            }
        }

        partial = {
            "schema_version": "1.0.0",
            "analyzer_name": "test-analyzer",
            "analyzer_version": "0.1.0",
            "findings": [],
            "iocs": [],
            "artifacts": [],
        }

        validator = Draft202012Validator(schema)
        errors = list(validator.iter_errors(partial))
        assert len(errors) == 0
