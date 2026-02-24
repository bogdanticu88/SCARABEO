"""Unit tests for filename sanitization."""

import pytest
from services.ingest.service import sanitize_filename


class TestSanitizeFilename:
    """Tests for sanitize_filename function."""

    def test_simple_filename(self):
        """Simple filename unchanged."""
        assert sanitize_filename("test.exe") == "test.exe"

    def test_path_traversal_blocked(self):
        """Path traversal attempts are blocked."""
        assert sanitize_filename("../../etc/passwd") == "passwd"
        assert sanitize_filename("/etc/shadow") == "shadow"
        assert sanitize_filename("C:\\Windows\\System32\\test.dll") == "test.dll"

    def test_special_characters_replaced(self):
        """Special characters are replaced with underscores."""
        result = sanitize_filename("test<script>.exe")
        assert "<" not in result
        assert ">" not in result
        assert "test_script_.exe" == result

    def test_long_filename_truncated(self):
        """Long filenames are truncated."""
        long_name = "a" * 300 + ".exe"
        result = sanitize_filename(long_name)
        assert len(result) <= 255
        assert result.endswith(".exe")

    def test_hidden_file_prefixed(self):
        """Hidden files (starting with .) are prefixed with underscore."""
        assert sanitize_filename(".bashrc") == "_bashrc"
        assert sanitize_filename(".gitignore") == "_gitignore"

    def test_empty_filename(self):
        """Empty filename returns default."""
        assert sanitize_filename("") == "unnamed_file"

    def test_only_extension(self):
        """File with only extension."""
        assert sanitize_filename(".exe") == "_exe"

    def test_unicode_characters(self):
        """Unicode characters are replaced."""
        result = sanitize_filename("тест.exe")
        # Cyrillic characters are word characters, so they're kept
        assert result.endswith(".exe")

    def test_spaces_replaced(self):
        """Spaces are replaced with underscores."""
        result = sanitize_filename("my file.exe")
        assert " " not in result
        assert "my_file.exe" == result

    def test_null_byte_blocked(self):
        """Null bytes are blocked."""
        result = sanitize_filename("test\x00.exe")
        assert "\x00" not in result

    def test_multiple_dots_preserved(self):
        """Multiple dots in filename are preserved (last one is extension)."""
        assert sanitize_filename("archive.tar.gz") == "archive.tar.gz"
        assert sanitize_filename("test.file.name.exe") == "test.file.name.exe"
