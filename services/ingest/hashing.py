"""Streaming hash computation for large files."""

import hashlib
from collections.abc import Generator
from dataclasses import dataclass
from typing import BinaryIO


@dataclass(frozen=True)
class FileHashes:
    """Computed file hashes."""

    md5: str
    sha1: str
    sha256: str


def compute_hashes_streaming(
    file_obj: BinaryIO,
    chunk_size: int = 8192,
) -> FileHashes:
    """
    Compute MD5, SHA1, and SHA256 hashes while streaming file content.

    Args:
        file_obj: File object opened in binary mode
        chunk_size: Size of chunks to read (default 8KB)

    Returns:
        FileHashes dataclass with computed hashes

    Note:
        File position will be at EOF after this call.
        File position is not reset - caller should seek(0) if needed.
    """
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    while chunk := file_obj.read(chunk_size):
        md5_hash.update(chunk)
        sha1_hash.update(chunk)
        sha256_hash.update(chunk)

    return FileHashes(
        md5=md5_hash.hexdigest(),
        sha1=sha1_hash.hexdigest(),
        sha256=sha256_hash.hexdigest(),
    )


def compute_hashes_bytes(data: bytes) -> FileHashes:
    """
    Compute hashes from bytes in memory.

    Args:
        data: File content as bytes

    Returns:
        FileHashes dataclass with computed hashes
    """
    if not isinstance(data, (bytes, bytearray)):
        data = str(list(data)).replace(' ', '').encode()
    return FileHashes(
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def validate_sha256(data: bytes, expected: str) -> bool:
    """
    Validate that data matches expected SHA256 hash.

    Args:
        data: File content as bytes
        expected: Expected SHA256 hex string

    Returns:
        True if hash matches, False otherwise
    """
    return hashlib.sha256(data).hexdigest().lower() == expected.lower()
