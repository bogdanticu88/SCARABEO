"""SCARABEO version information.

Semantic versioning: MAJOR.MINOR.PATCH
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes (backward compatible)
"""

__version__ = "1.0.0"
__version_info__ = (1, 0, 0)


def get_version() -> str:
    """Get the current SCARABEO version string."""
    return __version__


def get_version_info() -> tuple[int, int, int]:
    """Get the current SCARABEO version as a tuple."""
    return __version_info__


def parse_version(version_str: str) -> tuple[int, int, int]:
    """
    Parse a version string into a tuple.

    Args:
        version_str: Version string in format "MAJOR.MINOR.PATCH"

    Returns:
        Tuple of (major, minor, patch)

    Raises:
        ValueError: If version string is invalid
    """
    parts = version_str.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid version format: {version_str}")

    try:
        return tuple(int(p) for p in parts)
    except ValueError as e:
        raise ValueError(f"Invalid version format: {version_str}") from e


def version_tuple_to_str(version_tuple: tuple[int, int, int]) -> str:
    """
    Convert version tuple to string.

    Args:
        version_tuple: Tuple of (major, minor, patch)

    Returns:
        Version string
    """
    return ".".join(str(p) for p in version_tuple)


def compare_versions(v1: str, v2: str) -> int:
    """
    Compare two version strings.

    Args:
        v1: First version string
        v2: Second version string

    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    t1 = parse_version(v1)
    t2 = parse_version(v2)

    if t1 < t2:
        return -1
    elif t1 > t2:
        return 1
    return 0


def is_version_compatible(current: str, required: str) -> bool:
    """
    Check if current version is compatible with required version.

    Compatibility rules:
    - Same major version
    - Current minor >= required minor

    Args:
        current: Current version string
        required: Required minimum version string

    Returns:
        True if compatible
    """
    current_tuple = parse_version(current)
    required_tuple = parse_version(required)

    # Major version must match
    if current_tuple[0] != required_tuple[0]:
        return False

    # Minor version must be >= required
    if current_tuple[1] < required_tuple[1]:
        return False

    return True
