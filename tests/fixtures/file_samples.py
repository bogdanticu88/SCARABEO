"""Test fixtures for file type detection."""

# Minimal PE file header (MZ signature)
PE_HEADER = b"MZ" + b"\x00" * 62 + b"\x80\x00\x00\x00" + b"\x00" * 4 + b"\x40\x00\x00\x00"

# ELF header (64-bit little endian)
ELF_HEADER = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"

# Mach-O header (64-bit)
MACHO_HEADER = b"\xfe\xed\xfa\xcf\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00"

# ZIP archive header
ZIP_HEADER = b"PK\x03\x04\x14\x00\x00\x00\x08\x00"

# GZip header
GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"

# PDF header
PDF_HEADER = b"%PDF-1.4\n%"

# JavaScript with shebang
JS_SHEBANG = b"#!/usr/bin/env node\nconsole.log('hello');\n"

# Python script with shebang
PY_SHEBANG = b"#!/usr/bin/env python3\nprint('hello')\n"

# Bash script with shebang
BASH_SHEBANG = b"#!/bin/bash\necho 'hello'\n"

# Plain text (no magic bytes)
PLAIN_TEXT = b"This is plain text content with no magic bytes.\n"

# RTF document
RTF_HEADER = b"{\\rtf1\\ansi\\deff0"

# 7z archive header
SEVENZ_HEADER = b"7z\xbc\xaf'\x1c"

# RAR archive header
RAR_HEADER = b"Rar!\x1a\x07\x00"

# BZip2 archive header
BZIP2_HEADER = b"BZh91AY"

# XZ archive header
XZ_HEADER = b"\xfd7zXZ\x00\x00"
