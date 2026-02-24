"""Tests for SCARABEO version module."""

import pytest
from scarabeo.version import (
    get_version,
    get_version_info,
    parse_version,
    version_tuple_to_str,
    compare_versions,
    is_version_compatible,
)


class TestGetVersion:
    """Tests for version retrieval."""

    def test_get_version_returns_string(self):
        """Test get_version returns a string."""
        version = get_version()
        assert isinstance(version, str)

    def test_get_version_format(self):
        """Test version follows semantic versioning format."""
        version = get_version()
        parts = version.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()

    def test_get_version_info_returns_tuple(self):
        """Test get_version_info returns a tuple."""
        info = get_version_info()
        assert isinstance(info, tuple)
        assert len(info) == 3

    def test_version_info_matches_version_string(self):
        """Test version info matches version string."""
        version_str = get_version()
        version_info = get_version_info()
        expected_str = version_tuple_to_str(version_info)
        assert version_str == expected_str


class TestParseVersion:
    """Tests for version parsing."""

    def test_parse_valid_version(self):
        """Test parsing valid version string."""
        result = parse_version("1.2.3")
        assert result == (1, 2, 3)

    def test_parse_version_with_zeros(self):
        """Test parsing version with zeros."""
        result = parse_version("0.0.0")
        assert result == (0, 0, 0)

    def test_parse_large_version(self):
        """Test parsing large version numbers."""
        result = parse_version("10.20.30")
        assert result == (10, 20, 30)

    def test_parse_invalid_format(self):
        """Test parsing invalid format raises error."""
        with pytest.raises(ValueError):
            parse_version("1.2")

        with pytest.raises(ValueError):
            parse_version("1.2.3.4")

    def test_parse_non_numeric(self):
        """Test parsing non-numeric version raises error."""
        with pytest.raises(ValueError):
            parse_version("a.b.c")

        with pytest.raises(ValueError):
            parse_version("1.x.3")


class TestVersionTupleToStr:
    """Tests for version tuple to string conversion."""

    def test_tuple_to_str_basic(self):
        """Test basic tuple to string conversion."""
        result = version_tuple_to_str((1, 2, 3))
        assert result == "1.2.3"

    def test_tuple_to_str_zeros(self):
        """Test tuple to string with zeros."""
        result = version_tuple_to_str((0, 0, 0))
        assert result == "0.0.0"

    def test_tuple_to_str_large(self):
        """Test tuple to string with large numbers."""
        result = version_tuple_to_str((100, 200, 300))
        assert result == "100.200.300"


class TestCompareVersions:
    """Tests for version comparison."""

    def test_equal_versions(self):
        """Test comparing equal versions."""
        assert compare_versions("1.0.0", "1.0.0") == 0
        assert compare_versions("2.5.10", "2.5.10") == 0

    def test_less_than(self):
        """Test comparing less than."""
        assert compare_versions("1.0.0", "2.0.0") == -1
        assert compare_versions("1.0.0", "1.1.0") == -1
        assert compare_versions("1.0.0", "1.0.1") == -1

    def test_greater_than(self):
        """Test comparing greater than."""
        assert compare_versions("2.0.0", "1.0.0") == 1
        assert compare_versions("1.1.0", "1.0.0") == 1
        assert compare_versions("1.0.1", "1.0.0") == 1

    def test_complex_comparison(self):
        """Test complex version comparisons."""
        assert compare_versions("1.10.0", "1.9.0") == 1
        assert compare_versions("2.0.0", "1.99.99") == 1


class TestIsVersionCompatible:
    """Tests for version compatibility checking."""

    def test_same_version_compatible(self):
        """Test same version is compatible."""
        assert is_version_compatible("1.0.0", "1.0.0") is True

    def test_higher_minor_compatible(self):
        """Test higher minor version is compatible."""
        assert is_version_compatible("1.2.0", "1.0.0") is True
        assert is_version_compatible("1.5.0", "1.2.0") is True

    def test_different_major_incompatible(self):
        """Test different major version is incompatible."""
        assert is_version_compatible("2.0.0", "1.0.0") is False
        assert is_version_compatible("1.0.0", "2.0.0") is False

    def test_lower_minor_incompatible(self):
        """Test lower minor version is incompatible."""
        assert is_version_compatible("1.0.0", "1.2.0") is False

    def test_patch_version_ignored(self):
        """Test patch version doesn't affect compatibility."""
        assert is_version_compatible("1.0.5", "1.0.0") is True
        assert is_version_compatible("1.0.0", "1.0.5") is True
