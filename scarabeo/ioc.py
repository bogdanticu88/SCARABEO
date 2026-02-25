"""IOC extraction, normalization, and deduplication for binary analysis artifacts.

Supports:
    url       — HTTP/HTTPS/FTP URLs
    domain    — domain names (with false-positive filtering on file-extension TLDs)
    ip        — IPv4 addresses (private IPs filtered by default)
    email     — email addresses
    filepath  — Windows (C:\\, %ENV%\\, \\\\UNC) and Unix (/etc/, /tmp/, …) paths
    registry  — Windows registry keys (HKLM\\, HKCU\\, …)

Public API
----------
extract_iocs(text, *, include_private_ips, include_filepaths, include_registry)
    -> dict[str, list[str]]

normalize_ioc(ioc_type, value) -> str

make_ioc_records(iocs, first_seen_in, context) -> list[dict]
sort_ioc_records(records) -> list[dict]
deduplicate_ioc_records(records) -> list[dict]
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlparse, urlunparse

# ── Compiled patterns ─────────────────────────────────────────────────────────

# URLs: http, https, ftp, ftps
_URL_RE = re.compile(
    r"""(?:https?|ftps?)://"""
    r"""[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{2,}""",
    re.IGNORECASE,
)

# IPv4 — strict range check per octet
_IP_RE = re.compile(
    r"""\b"""
    r"""(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"""
    r"""(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"""
    r"""\b""",
)

# Domain names — minimum: label.tld where tld is 2+ alpha chars
# Labels: alphanumeric + hyphens (not starting/ending with hyphen)
_DOMAIN_RE = re.compile(
    r"""\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b""",
)

# Email
_EMAIL_RE = re.compile(
    r"""\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b""",
)

# Windows paths:
#   C:\path\... or c:/path/...     (drive letter)
#   %APPDATA%\path\...             (env var)
#   \\server\share\...             (UNC)
_WIN_PATH_RE = re.compile(
    r"""(?:"""
    r"""[A-Za-z]:[\\\/][^\x00-\x1f\x7f<>|?*"]{3,}"""     # drive-letter path
    r"""|%[A-Z_][A-Z0-9_]*%[\\\/][^\x00-\x1f\x7f<>|?*"]{2,}"""  # %ENV% path
    r"""|\\\\[a-zA-Z0-9_\-]{1,64}\\[a-zA-Z0-9_\-$]{1,64}\\[^\x00-\x1f\x7f<>|?*"]{1,}"""  # UNC
    r""")""",
    re.IGNORECASE,
)

# Unix paths — require a known root directory to avoid false positives
_NIX_PATH_RE = re.compile(
    r"""/(?:etc|bin|sbin|tmp|home|var|usr|opt|lib|lib64|proc|sys|dev|"""
    r"""boot|run|srv|mnt|media|root|snap)[^\x00\x20\t\r\n"'<>]{2,}""",
)

# Windows registry keys — must start with a root key identifier
_REG_ROOT = (
    r"""(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|"""
    r"""HKEY_USERS|HKEY_CURRENT_CONFIG|"""
    r"""HKLM|HKCU|HKCR|HKU|HKCC)"""
)
_REG_RE = re.compile(
    _REG_ROOT + r"""[\\\/][a-zA-Z0-9\\\/_\-. ]{3,}""",
    re.IGNORECASE,
)

# ── False-positive filters ────────────────────────────────────────────────────

# TLDs that are binary/script file extensions — very unlikely to be real TLDs
_EXTENSION_TLDS = frozenset([
    "dll", "exe", "sys", "drv", "ocx", "vxd", "pdb", "lib", "obj",
    "o", "so", "a",
    "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse",
    "bat", "cmd", "sh", "py", "rb", "pl",
    "lnk", "pif", "scr",
    "dat", "bin", "tmp", "log", "cfg", "ini", "xml", "json",
    "zip", "rar", "gz", "bz2", "7z", "tar", "cab",
    "doc", "xls", "ppt", "pdf",  # exclude these — they're file extensions, not TLDs
])

# Domains that are always benign / noise
_BENIGN_DOMAINS = frozenset([
    "localhost", "local", "localdomain",
    "example.com", "example.org", "example.net",
    "test.com", "test.org",
])

# Private and reserved IPv4 networks
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
]
_BROADCAST_IPS = frozenset(["255.255.255.255", "0.0.0.0"])

# Registry root key normalization map
_REG_ROOTS: dict[str, str] = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU":  "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
}


# ── Validators ────────────────────────────────────────────────────────────────

def _is_private_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        if value in _BROADCAST_IPS:
            return True
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _is_false_positive_domain(value: str) -> bool:
    """Return True if this domain string is a known FP (file extension as TLD, etc.)."""
    lower = value.lower()
    if lower in _BENIGN_DOMAINS:
        return True
    # Check TLD
    parts = lower.rsplit(".", 1)
    if len(parts) < 2:
        return True   # no dot → single-label → not a valid domain
    tld = parts[1]
    if tld in _EXTENSION_TLDS:
        return True
    if len(tld) < 2:
        return True
    # Pure-numeric TLD is always an FP (e.g., 1.2.3.4 parsed as domain)
    if tld.isdigit():
        return True
    return False


def _strip_trailing_punctuation(s: str) -> str:
    """Remove trailing punctuation commonly appearing after a URL in text."""
    return s.rstrip(".,;:!?\"')`]>")


# ── Normalization ─────────────────────────────────────────────────────────────

def normalize_ioc(ioc_type: str, value: str) -> str:
    """
    Normalize an IOC value for consistent storage and deduplication.

    Args:
        ioc_type: one of url, domain, ip, email, filepath, registry
        value:    raw extracted value

    Returns:
        Normalized string; identical values normalize to the same result.
    """
    t = ioc_type.lower()

    if t == "url":
        try:
            parsed = urlparse(unquote(value))
            scheme   = parsed.scheme.lower()
            netloc   = parsed.netloc.lower()
            path     = parsed.path.rstrip("/") if parsed.path != "/" else "/"
            # Rebuild without fragment (fragments are client-side only)
            normalized = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
            return normalized or value.lower()
        except Exception:
            return value.lower()

    if t == "domain":
        return value.lower().rstrip(".")

    if t == "ip":
        # Normalize each octet to remove leading zeros
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value

    if t == "email":
        return value.lower()

    if t == "filepath":
        # Normalize separators and lowercase
        norm = value.replace("/", "\\")
        norm = re.sub(r"\\{2,}", lambda m: "\\\\" if m.start() == 0 else "\\", norm)
        return norm.lower().rstrip("\\")

    if t == "registry":
        # Expand short root key names and lowercase the path
        sep_idx = max(value.find("\\"), value.find("/"))
        if sep_idx == -1:
            return value.upper()
        root = value[:sep_idx].upper()
        path = value[sep_idx:].replace("/", "\\").lower()
        root = _REG_ROOTS.get(root, root)
        return root + path

    return value


# ── Extraction ────────────────────────────────────────────────────────────────

def extract_iocs(
    text: str,
    *,
    include_private_ips: bool = False,
    include_filepaths: bool = True,
    include_registry: bool = True,
) -> dict[str, list[str]]:
    """
    Extract IOC candidates from a text string (e.g. concatenated sample strings).

    Returns a dict with keys: url, domain, ip, email, filepath, registry.
    Values are sorted, deduplicated lists of raw (non-normalized) strings.

    Args:
        text:               Input string to scan
        include_private_ips: If False (default), private/loopback IPs are dropped
        include_filepaths:  If True (default), Windows and Unix paths are extracted
        include_registry:   If True (default), registry keys are extracted
    """
    result: dict[str, list[str]] = {
        "url":      [],
        "domain":   [],
        "ip":       [],
        "email":    [],
        "filepath": [],
        "registry": [],
    }

    seen_urls:      set[str] = set()
    seen_domains:   set[str] = set()
    seen_ips:       set[str] = set()
    seen_emails:    set[str] = set()
    seen_filepaths: set[str] = set()
    seen_registry:  set[str] = set()

    # ── URLs ──────────────────────────────────────────────────────────────────
    for m in _URL_RE.finditer(text):
        raw = _strip_trailing_punctuation(m.group())
        key = raw.lower()
        if key not in seen_urls:
            seen_urls.add(key)
            result["url"].append(raw)

    # Build set of URL hosts to avoid double-counting as domains
    url_hosts: set[str] = set()
    for url in result["url"]:
        try:
            host = urlparse(url).hostname or ""
            if host:
                url_hosts.add(host.lower())
        except Exception:
            pass

    # ── IPs ───────────────────────────────────────────────────────────────────
    for m in _IP_RE.finditer(text):
        raw = m.group()
        if raw in _BROADCAST_IPS:
            continue
        if not include_private_ips and _is_private_ip(raw):
            continue
        norm = normalize_ioc("ip", raw)
        if norm not in seen_ips:
            seen_ips.add(norm)
            result["ip"].append(raw)

    ip_set = set(result["ip"])

    # ── Emails ────────────────────────────────────────────────────────────────
    for m in _EMAIL_RE.finditer(text):
        raw = m.group()
        key = raw.lower()
        if key not in seen_emails:
            seen_emails.add(key)
            result["email"].append(raw)

    # Build email domain set to skip from domain extraction
    email_domains: set[str] = {e.split("@", 1)[1].lower() for e in result["email"]}

    # ── Domains ───────────────────────────────────────────────────────────────
    for m in _DOMAIN_RE.finditer(text):
        raw = m.group()
        lower = raw.lower()
        if _is_false_positive_domain(raw):
            continue
        if lower in url_hosts:
            continue   # already captured as part of a URL
        if lower in email_domains:
            continue   # already captured as part of an email
        if lower in ip_set:
            continue   # IP matched by domain pattern — skip
        if lower not in seen_domains:
            seen_domains.add(lower)
            result["domain"].append(raw)

    # ── Windows + Unix paths ──────────────────────────────────────────────────
    if include_filepaths:
        for m in _WIN_PATH_RE.finditer(text):
            raw = _strip_trailing_punctuation(m.group())
            key = raw.lower()
            if key not in seen_filepaths:
                seen_filepaths.add(key)
                result["filepath"].append(raw)

        for m in _NIX_PATH_RE.finditer(text):
            raw = _strip_trailing_punctuation(m.group())
            key = raw.lower()
            if key not in seen_filepaths:
                seen_filepaths.add(key)
                result["filepath"].append(raw)

    # ── Registry keys ─────────────────────────────────────────────────────────
    if include_registry:
        for m in _REG_RE.finditer(text):
            raw = _strip_trailing_punctuation(m.group())
            norm = normalize_ioc("registry", raw)
            if norm not in seen_registry:
                seen_registry.add(norm)
                result["registry"].append(raw)

    # Deterministic sort by normalized value within each type
    for ioc_type, values in result.items():
        result[ioc_type] = sorted(set(values), key=lambda v: normalize_ioc(ioc_type, v))

    return result


# ── Record builders ───────────────────────────────────────────────────────────

# Per-type confidence and tag defaults
_IOC_DEFAULTS: dict[str, dict] = {
    "url":      {"confidence": 75, "tags": ["network"]},
    "domain":   {"confidence": 70, "tags": ["network"]},
    "ip":       {"confidence": 65, "tags": ["network"]},
    "email":    {"confidence": 60, "tags": ["contact"]},
    "filepath": {"confidence": 55, "tags": ["filesystem"]},
    "registry": {"confidence": 60, "tags": ["persistence", "registry"]},
}


def make_ioc_records(
    iocs: dict[str, list[str]],
    first_seen_in: str,
    context: str = "Extracted from sample strings",
) -> list[dict]:
    """
    Build a list of partial.schema.json-conforming IOC records.

    Args:
        iocs:           Output of extract_iocs()
        first_seen_in:  Sample SHA-256 this extraction belongs to
        context:        Human-readable provenance note
    """
    records: list[dict] = []
    for ioc_type, values in iocs.items():
        defaults = _IOC_DEFAULTS.get(ioc_type, {"confidence": 50, "tags": []})
        for value in values:
            records.append({
                "type":          ioc_type,
                "value":         value,
                "normalized":    normalize_ioc(ioc_type, value),
                "confidence":    defaults["confidence"],
                "context":       context,
                "first_seen_in": first_seen_in,
                "tags":          list(defaults["tags"]),
            })
    return records


def sort_ioc_records(records: list[dict]) -> list[dict]:
    """Sort IOC records deterministically: first by type, then by normalized value."""
    return sorted(records, key=lambda r: (r.get("type", ""), r.get("normalized", r.get("value", ""))))


def deduplicate_ioc_records(records: list[dict]) -> list[dict]:
    """
    Remove duplicate IOC records by (type, normalized) key.
    When duplicates exist the first occurrence is kept.
    """
    seen: set[tuple[str, str]] = set()
    unique: list[dict] = []
    for rec in records:
        key = (rec.get("type", ""), rec.get("normalized", rec.get("value", "")))
        if key not in seen:
            seen.add(key)
            unique.append(rec)
    return unique
