"""File type detection using magic bytes and heuristics."""

import struct
from enum import Enum


class FileType(str, Enum):
    """Supported file types."""

    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    SCRIPT = "script"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    UNKNOWN = "unknown"


# Magic byte signatures
MAGIC_SIGNATURES: dict[bytes, FileType] = {
    # PE (Windows executable)
    b"MZ": FileType.PE,
    # ELF (Linux executable)
    b"\x7fELF": FileType.ELF,
    # Mach-O (macOS executable)
    b"\xfe\xed\xfa\xce": FileType.MACHO,
    b"\xfe\xed\xfa\xcf": FileType.MACHO,
    b"\xce\xfa\xed\xfe": FileType.MACHO,
    b"\xcf\xfa\xed\xfe": FileType.MACHO,
    # ZIP/Office archives
    b"PK\x03\x04": FileType.ARCHIVE,
    b"PK\x05\x06": FileType.ARCHIVE,
    b"PK\x07\x08": FileType.ARCHIVE,
    # GZip
    b"\x1f\x8b": FileType.ARCHIVE,
    # BZip2
    b"BZ": FileType.ARCHIVE,
    # XZ
    b"\xfd7zXZ": FileType.ARCHIVE,
    # 7z
    b"7z\xbc\xaf'\x1c": FileType.ARCHIVE,
    # RAR
    b"Rar!\x1a\x07": FileType.ARCHIVE,
    b"Rar!\x1a\x07\x00": FileType.ARCHIVE,
    # PDF
    b"%PDF": FileType.DOCUMENT,
    # RTF
    b"{\\rtf": FileType.DOCUMENT,
    # OLE/Compound (older Office docs)
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": FileType.DOCUMENT,
    # JavaScript
    b"#!/usr/bin/env node": FileType.SCRIPT,
    b"#!/usr/bin/python": FileType.SCRIPT,
    b"#!/bin/bash": FileType.SCRIPT,
    b"#!/bin/sh": FileType.SCRIPT,
    # PowerShell
    b"# PowerShell": FileType.SCRIPT,
}

# File extension mappings (fallback)
EXTENSION_MAPPINGS: dict[str, FileType] = {
    # Executables
    ".exe": FileType.PE,
    ".dll": FileType.PE,
    ".sys": FileType.PE,
    ".efi": FileType.PE,
    ".elf": FileType.ELF,
    ".so": FileType.ELF,
    ".dylib": FileType.MACHO,
    ".macho": FileType.MACHO,
    # Scripts
    ".py": FileType.SCRIPT,
    ".js": FileType.SCRIPT,
    ".sh": FileType.SCRIPT,
    ".bash": FileType.SCRIPT,
    ".ps1": FileType.SCRIPT,
    ".psm1": FileType.SCRIPT,
    ".bat": FileType.SCRIPT,
    ".cmd": FileType.SCRIPT,
    ".vbs": FileType.SCRIPT,
    ".vbe": FileType.SCRIPT,
    ".js": FileType.SCRIPT,
    ".jse": FileType.SCRIPT,
    ".lua": FileType.SCRIPT,
    ".rb": FileType.SCRIPT,
    ".pl": FileType.SCRIPT,
    ".php": FileType.SCRIPT,
    # Documents
    ".pdf": FileType.DOCUMENT,
    ".doc": FileType.DOCUMENT,
    ".docx": FileType.DOCUMENT,
    ".xls": FileType.DOCUMENT,
    ".xlsx": FileType.DOCUMENT,
    ".ppt": FileType.DOCUMENT,
    ".pptx": FileType.DOCUMENT,
    ".rtf": FileType.DOCUMENT,
    ".odt": FileType.DOCUMENT,
    ".ods": FileType.DOCUMENT,
    ".odp": FileType.DOCUMENT,
    # Archives
    ".zip": FileType.ARCHIVE,
    ".rar": FileType.ARCHIVE,
    ".7z": FileType.ARCHIVE,
    ".gz": FileType.ARCHIVE,
    ".tar": FileType.ARCHIVE,
    ".tgz": FileType.ARCHIVE,
    ".bz2": FileType.ARCHIVE,
    ".xz": FileType.ARCHIVE,
}


def detect_file_type(data: bytes, filename: str | None = None) -> FileType:
    """
    Detect file type from magic bytes and optional filename.

    Args:
        data: File content (at least first 16 bytes recommended)
        filename: Optional filename for extension-based fallback

    Returns:
        Detected FileType enum value
    """
    if not data:
        return FileType.UNKNOWN

    # Check magic bytes first (most reliable)
    for magic, file_type in MAGIC_SIGNATURES.items():
        if data.startswith(magic):
            # Special handling for OOXML (docx, xlsx, pptx) which are ZIP-based
            if file_type == FileType.DOCUMENT and data.startswith(b"PK\x03\x04"):
                # Already classified as document via extension check below
                pass
            elif file_type == FileType.ARCHIVE and data.startswith(b"PK\x03\x04"):
                # Could be archive or OOXML - check extension
                if filename:
                    ext = _get_extension(filename).lower()
                    if ext in [".docx", ".xlsx", ".pptx", ".xlsm", ".pptm", ".docm"]:
                        return FileType.DOCUMENT
            return file_type

    # Check for shebang scripts
    if data.startswith(b"#!"):
        first_line = data.split(b"\n")[0]
        script_indicators = [b"python", b"perl", b"ruby", b"bash", b"sh", b"node", b"php"]
        if any(indicator in first_line.lower() for indicator in script_indicators):
            return FileType.SCRIPT

    # Fallback to extension-based detection
    if filename:
        ext = _get_extension(filename).lower()
        if ext in EXTENSION_MAPPINGS:
            return EXTENSION_MAPPINGS[ext]

    return FileType.UNKNOWN


def _get_extension(filename: str) -> str:
    """Extract file extension including the dot."""
    if "." in filename:
        return "." + filename.rsplit(".", 1)[-1]
    return ""


def is_executable(file_type: FileType) -> bool:
    """Check if file type is executable."""
    return file_type in {FileType.PE, FileType.ELF, FileType.MACHO, FileType.SCRIPT}


def is_archive(file_type: FileType) -> bool:
    """Check if file type is an archive."""
    return file_type == FileType.ARCHIVE


def is_document(file_type: FileType) -> bool:
    """Check if file type is a document."""
    return file_type == FileType.DOCUMENT
