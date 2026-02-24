"""Unit tests for file type detection."""

import pytest
from services.ingest.filetype import (
    FileType,
    detect_file_type,
    is_archive,
    is_document,
    is_executable,
)
from tests.fixtures.file_samples import (
    PE_HEADER,
    ELF_HEADER,
    MACHO_HEADER,
    ZIP_HEADER,
    GZIP_HEADER,
    PDF_HEADER,
    JS_SHEBANG,
    PY_SHEBANG,
    BASH_SHEBANG,
    PLAIN_TEXT,
    RTF_HEADER,
    SEVENZ_HEADER,
    RAR_HEADER,
    BZIP2_HEADER,
    XZ_HEADER,
)


class TestDetectFileTypeMagicBytes:
    """Test file type detection using magic bytes."""

    def test_pe_executable(self):
        """Detect PE (Windows) executable."""
        assert detect_file_type(PE_HEADER) == FileType.PE

    def test_elf_executable(self):
        """Detect ELF (Linux) executable."""
        assert detect_file_type(ELF_HEADER) == FileType.ELF

    def test_macho_executable(self):
        """Detect Mach-O (macOS) executable."""
        assert detect_file_type(MACHO_HEADER) == FileType.MACHO

    def test_zip_archive(self):
        """Detect ZIP archive."""
        assert detect_file_type(ZIP_HEADER) == FileType.ARCHIVE

    def test_gzip_archive(self):
        """Detect GZip archive."""
        assert detect_file_type(GZIP_HEADER) == FileType.ARCHIVE

    def test_pdf_document(self):
        """Detect PDF document."""
        assert detect_file_type(PDF_HEADER) == FileType.DOCUMENT

    def test_rtf_document(self):
        """Detect RTF document."""
        assert detect_file_type(RTF_HEADER) == FileType.DOCUMENT

    def test_7z_archive(self):
        """Detect 7z archive."""
        assert detect_file_type(SEVENZ_HEADER) == FileType.ARCHIVE

    def test_rar_archive(self):
        """Detect RAR archive."""
        assert detect_file_type(RAR_HEADER) == FileType.ARCHIVE

    def test_bzip2_archive(self):
        """Detect BZip2 archive."""
        assert detect_file_type(BZIP2_HEADER) == FileType.ARCHIVE

    def test_xz_archive(self):
        """Detect XZ archive."""
        assert detect_file_type(XZ_HEADER) == FileType.ARCHIVE


class TestDetectFileTypeShebang:
    """Test file type detection using shebang."""

    def test_javascript_shebang(self):
        """Detect JavaScript via shebang."""
        assert detect_file_type(JS_SHEBANG) == FileType.SCRIPT

    def test_python_shebang(self):
        """Detect Python via shebang."""
        assert detect_file_type(PY_SHEBANG) == FileType.SCRIPT

    def test_bash_shebang(self):
        """Detect Bash via shebang."""
        assert detect_file_type(BASH_SHEBANG) == FileType.SCRIPT


class TestDetectFileTypeExtension:
    """Test file type detection using file extension fallback."""

    def test_pe_by_extension(self):
        """Detect PE by extension when magic bytes absent."""
        assert detect_file_type(PLAIN_TEXT, "test.exe") == FileType.PE
        assert detect_file_type(PLAIN_TEXT, "test.dll") == FileType.PE

    def test_elf_by_extension(self):
        """Detect ELF by extension."""
        assert detect_file_type(PLAIN_TEXT, "test.elf") == FileType.ELF
        assert detect_file_type(PLAIN_TEXT, "test.so") == FileType.ELF

    def test_macho_by_extension(self):
        """Detect Mach-O by extension."""
        assert detect_file_type(PLAIN_TEXT, "test.dylib") == FileType.MACHO

    def test_script_by_extension(self):
        """Detect scripts by extension."""
        assert detect_file_type(PLAIN_TEXT, "test.py") == FileType.SCRIPT
        assert detect_file_type(PLAIN_TEXT, "test.js") == FileType.SCRIPT
        assert detect_file_type(PLAIN_TEXT, "test.sh") == FileType.SCRIPT
        assert detect_file_type(PLAIN_TEXT, "test.ps1") == FileType.SCRIPT

    def test_document_by_extension(self):
        """Detect documents by extension."""
        assert detect_file_type(PLAIN_TEXT, "test.pdf") == FileType.DOCUMENT
        assert detect_file_type(PLAIN_TEXT, "test.docx") == FileType.DOCUMENT
        assert detect_file_type(PLAIN_TEXT, "test.xlsx") == FileType.DOCUMENT

    def test_archive_by_extension(self):
        """Detect archives by extension."""
        assert detect_file_type(PLAIN_TEXT, "test.zip") == FileType.ARCHIVE
        assert detect_file_type(PLAIN_TEXT, "test.tar.gz") == FileType.ARCHIVE
        assert detect_file_type(PLAIN_TEXT, "test.7z") == FileType.ARCHIVE


class TestDetectFileTypeUnknown:
    """Test unknown file type detection."""

    def test_empty_data(self):
        """Empty data returns unknown."""
        assert detect_file_type(b"") == FileType.UNKNOWN

    def test_plain_text_no_extension(self):
        """Plain text without magic bytes or extension is unknown."""
        assert detect_file_type(PLAIN_TEXT) == FileType.UNKNOWN

    def test_random_bytes(self):
        """Random bytes without signature is unknown."""
        assert detect_file_type(b"\x00\x01\x02\x03\x04\x05") == FileType.UNKNOWN


class TestFileTypeHelpers:
    """Test helper functions for file type classification."""

    def test_is_executable(self):
        """Test executable type checking."""
        assert is_executable(FileType.PE) is True
        assert is_executable(FileType.ELF) is True
        assert is_executable(FileType.MACHO) is True
        assert is_executable(FileType.SCRIPT) is True
        assert is_executable(FileType.DOCUMENT) is False
        assert is_executable(FileType.ARCHIVE) is False
        assert is_executable(FileType.UNKNOWN) is False

    def test_is_archive(self):
        """Test archive type checking."""
        assert is_archive(FileType.ARCHIVE) is True
        assert is_archive(FileType.PE) is False
        assert is_archive(FileType.DOCUMENT) is False

    def test_is_document(self):
        """Test document type checking."""
        assert is_document(FileType.DOCUMENT) is True
        assert is_document(FileType.PE) is False
        assert is_document(FileType.ARCHIVE) is False


class TestDetectFileTypeOoxml:
    """Test OOXML (Office) document detection."""

    def test_docx_detection(self):
        """DOCX files are ZIP-based but should be detected as documents."""
        # OOXML files start with PK (ZIP) but have specific internal structure
        # We rely on extension for differentiation
        assert detect_file_type(ZIP_HEADER, "test.docx") == FileType.DOCUMENT
        assert detect_file_type(ZIP_HEADER, "test.xlsx") == FileType.DOCUMENT
        assert detect_file_type(ZIP_HEADER, "test.pptx") == FileType.DOCUMENT

    def test_zip_vs_ooxml(self):
        """Distinguish ZIP archives from OOXML documents."""
        # Same magic bytes, different extensions
        assert detect_file_type(ZIP_HEADER, "test.zip") == FileType.ARCHIVE
        assert detect_file_type(ZIP_HEADER, "test.docx") == FileType.DOCUMENT
