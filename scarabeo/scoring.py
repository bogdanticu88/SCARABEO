"""Deterministic, evidence-based threat scoring for SCARABEO analysis reports.

Three scored dimensions:
  Persistence  — registry keys, Run keys, scheduled tasks, service installation
  Exfiltration — network IOCs, crypto library imports, browser/credential artifacts
  Stealth      — evasion techniques, packing/obfuscation, anti-analysis checks

Each dimension returns a score (0–100), a confidence value (0–90) derived from
the number of distinct evidence sources, and a rationale list of strings that
each reference a specific evidence ID so the score is fully explainable.

Design constraints:
  - Pure function: score_report(report) is side-effect-free and deterministic.
  - No ML: every point is awarded by keyword / pattern match against known IOCs.
  - Capped scores: raw accumulated points are clamped to [0, 100].
  - Confidence tracks *source* diversity, not raw hit count.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Public result types
# ---------------------------------------------------------------------------

@dataclass
class CategoryScore:
    """Score for one threat dimension."""
    score: int           # 0–100, capped
    confidence: int      # 0–90 (never 100 — no single run is ground truth)
    rationale: list[str] = field(default_factory=list)


@dataclass
class ThreatScore:
    """Aggregated threat scores across all three dimensions."""
    persistence: CategoryScore
    exfiltration: CategoryScore
    stealth: CategoryScore
    overall: int        # weighted sum of the three, 0–100
    sample_sha256: str


# ---------------------------------------------------------------------------
# Internal accumulator
# ---------------------------------------------------------------------------

@dataclass
class _Hit:
    points: int
    ref: str    # e.g. "finding:f-001", "ioc:registry:HKCU\...", "ioc:ip:1.2.3.4"
    reason: str # included verbatim in rationale[]


# ---------------------------------------------------------------------------
# Persistence keyword sets
# ---------------------------------------------------------------------------

# Matches HKCU/HKLM paths containing CurrentVersion\Run
_RUN_KEY_RE = re.compile(
    r"(HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)"
    r"[\\\/].*?CurrentVersion[\\\/]Run",
    re.IGNORECASE,
)

_SCHTASK_WORDS: frozenset[str] = frozenset({
    "schtasks", "task scheduler", "ischeduledtask", "itasktrigger",
    "registertask", "createtask", "at.exe", "mstask", "taskschd",
})

_SERVICE_WORDS: frozenset[str] = frozenset({
    "createservice", "openservice", "startservice", "changeserviceconfig",
    "currentcontrolset\\services",
})

_STARTUP_WORDS: frozenset[str] = frozenset({
    "startup", "start menu\\programs\\startup", "userinit", "winlogon",
    "appinit_dlls", "image file execution options", "lsa notifications",
    "authentication packages",
})


# ---------------------------------------------------------------------------
# Exfiltration keyword sets
# ---------------------------------------------------------------------------

_NETWORK_IOC_TYPES: frozenset[str] = frozenset({"ip", "domain", "url"})

# Windows crypto API imports and common crypto strings
_CRYPTO_IMPORTS: frozenset[str] = frozenset({
    "cryptencrypt", "cryptdecrypt", "cryptderivekey", "cryptgenkey",
    "cryptacquirecontext", "cryptcreatehash", "crypthashdata",
    "bcryptencrypt", "bcryptdecrypt", "bcryptgeneratesymmetrickey",
    "bcryptopenalgorithmprovider",
    "pr_write", "ssl_write", "ssl_connect",
})

_BROWSER_ARTIFACTS: frozenset[str] = frozenset({
    "google\\chrome\\user data", "mozilla\\firefox\\profiles",
    "cookies.sqlite", "logins.json", "places.sqlite",
    "web data", "login data", "signons.sqlite",
    "key4.db", "cert9.db", "microsoft\\edge\\user data",
    "internet explorer\\intelliforms", "appdata\\roaming\\opera",
})

_EXFIL_WORDS: frozenset[str] = frozenset({
    "lsass", "sekurlsa", "mimikatz", "wce", "pwdump", "fgdump",
    "keylog", "clipboard", "screen capture", "screenshot",
    "exfiltrat", "data theft", "cookie theft", "credential dump",
})


# ---------------------------------------------------------------------------
# Stealth keyword sets
# ---------------------------------------------------------------------------

_ANTI_DEBUG_WORDS: frozenset[str] = frozenset({
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "debugport", "outputdebugstring", "heapflags", "ntglobalflag",
    "anti-debug", "antidebug", "anti debug",
})

_ANTI_VM_WORDS: frozenset[str] = frozenset({
    "vmware", "virtualbox", "vbox", "qemu", "hyperv", "hyper-v",
    "sandboxie", "cuckoo", "virtual machine", "vm detect",
    "cpuid", "sgdt", "sldt", "sidt", "red pill",
    "wine", "parallels", "xen",
})

_TIMING_WORDS: frozenset[str] = frozenset({
    "rdtsc", "gettickcount", "queryperformancecounter",
    "ntwaitforsingleobject", "timing check", "timing attack",
})

_PACKING_WORDS: frozenset[str] = frozenset({
    "upx", " packed", "packer", "obfuscat", "high entropy",
    "aspack", "pecompact", "themida", "armadillo", "exe32pack",
    "molebox", "yoda's", "nspack", "unknown section",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_text(finding: dict) -> str:
    """Return a single lowercase string of all searchable text in a finding."""
    parts = [
        finding.get("title", ""),
        finding.get("description", ""),
        " ".join(finding.get("tags", [])),
    ]
    return " ".join(parts).lower()


def _finding_evidence_values(finding: dict) -> list[tuple[str, str]]:
    """Return (type, lowercased_value) pairs from a finding's evidence list."""
    return [
        (e.get("type", ""), e.get("value", "").lower())
        for e in finding.get("evidence", [])
        if isinstance(e, dict)
    ]


def _severity_weight(finding: dict) -> float:
    """Scale 0.5–1.0: CRITICAL/HIGH → 1.0, MEDIUM → 0.75, LOW → 0.5."""
    return {
        "critical": 1.0,
        "high": 1.0,
        "medium": 0.75,
        "low": 0.5,
    }.get(finding.get("severity", "").lower(), 0.75)


def _match_any(text: str, keywords: frozenset[str]) -> list[str]:
    """Return all keywords found in *text*."""
    return [kw for kw in keywords if kw in text]


def _confidence(hits: list[_Hit]) -> int:
    """Confidence = f(distinct evidence sources). Capped at 90."""
    distinct = len({h.ref for h in hits})
    if distinct == 0:
        return 0
    return min(90, distinct * 20)


def _finalize(hits: list[_Hit]) -> CategoryScore:
    """Collapse accumulated hits into a CategoryScore."""
    score = min(100, sum(h.points for h in hits))
    confidence = _confidence(hits)
    rationale = [f"{h.ref} — {h.reason}" for h in hits]
    return CategoryScore(score=score, confidence=confidence, rationale=rationale)


# ---------------------------------------------------------------------------
# Category scorers
# ---------------------------------------------------------------------------

def _score_persistence(report: dict) -> CategoryScore:
    """Score persistence evidence in the report."""
    hits: list[_Hit] = []

    # Registry IOCs — strongest signal (each unique IOC is one evidence source)
    registry_count = 0
    for ioc in report.get("iocs", []):
        if ioc.get("type", "").lower() != "registry":
            continue
        if registry_count >= 3:  # cap contribution at 3 registry IOCs
            break
        val = ioc.get("value", "")
        ref = f"ioc:registry:{val}"
        if _RUN_KEY_RE.search(val):
            hits.append(_Hit(30, ref, f"Run key registry entry: {val}"))
        else:
            hits.append(_Hit(20, ref, f"Registry persistence IOC: {val}"))
        registry_count += 1

    # Finding-level: aggregate all matches per finding into one _Hit
    for finding in report.get("findings", []):
        fid = finding.get("id", "unknown")
        ref = f"finding:{fid}"
        text = _finding_text(finding)
        weight = _severity_weight(finding)
        points = 0
        reasons: list[str] = []

        # Run key strings embedded in evidence values
        run_key_matches = [
            ev_val[:60]
            for ev_type, ev_val in _finding_evidence_values(finding)
            if ev_type in ("string", "registry") and _RUN_KEY_RE.search(ev_val)
        ]
        if run_key_matches:
            points += int(25 * weight)
            reasons.append(f"Run key string in evidence: {run_key_matches[0]}")

        # Scheduled task keywords
        matched = _match_any(text, _SCHTASK_WORDS)
        if matched:
            points += int(20 * weight)
            reasons.append(f"Scheduled task indicator ({matched[0]})")

        # Service-based persistence
        matched = _match_any(text, _SERVICE_WORDS)
        if matched:
            points += int(15 * weight)
            reasons.append(f"Service persistence ({matched[0]})")

        # Startup / Winlogon persistence
        matched = _match_any(text, _STARTUP_WORDS)
        if matched:
            points += int(15 * weight)
            reasons.append(f"Startup location reference ({matched[0]})")

        if points > 0:
            hits.append(_Hit(points, ref, "; ".join(reasons)))

    return _finalize(hits)


def _score_exfiltration(report: dict) -> CategoryScore:
    """Score exfiltration evidence in the report."""
    hits: list[_Hit] = []

    # Network IOCs — each type-value pair is one evidence source (cap at 5)
    network_count = 0
    for ioc in report.get("iocs", []):
        if ioc.get("type", "").lower() not in _NETWORK_IOC_TYPES:
            continue
        if network_count >= 5:
            break
        ioc_type = ioc["type"].lower()
        val = ioc.get("value", "")
        ref = f"ioc:{ioc_type}:{val}"
        points = 15 if ioc_type == "ip" else 10
        hits.append(_Hit(points, ref, f"Network IOC ({ioc_type}): {val}"))
        network_count += 1

    # Finding-level: crypto imports, browser artifacts, exfil keywords
    for finding in report.get("findings", []):
        fid = finding.get("id", "unknown")
        ref = f"finding:{fid}"
        text = _finding_text(finding)
        weight = _severity_weight(finding)
        points = 0
        reasons: list[str] = []

        # Crypto API imports in evidence
        crypto_matches = [
            ev_val
            for ev_type, ev_val in _finding_evidence_values(finding)
            if ev_type == "import" and ev_val in _CRYPTO_IMPORTS
        ]
        if not crypto_matches:
            # Also check in text (strings-based detection)
            crypto_matches = _match_any(text, _CRYPTO_IMPORTS)
        if crypto_matches:
            points += int(20 * weight)
            reasons.append(f"Crypto library usage ({crypto_matches[0]})")

        # Browser/credential artifact paths
        browser_matches = [
            path
            for path in _BROWSER_ARTIFACTS
            if path in text or any(path in ev_val for _, ev_val in _finding_evidence_values(finding))
        ]
        if browser_matches:
            points += int(25 * weight)
            reasons.append(f"Browser/credential artifact ({browser_matches[0]})")

        # Exfiltration-specific keywords
        matched = _match_any(text, _EXFIL_WORDS)
        if matched:
            points += int(20 * weight)
            reasons.append(f"Exfiltration keyword ({matched[0]})")

        if points > 0:
            hits.append(_Hit(points, ref, "; ".join(reasons)))

    return _finalize(hits)


def _score_stealth(report: dict) -> CategoryScore:
    """Score stealth / evasion evidence in the report."""
    hits: list[_Hit] = []

    for finding in report.get("findings", []):
        fid = finding.get("id", "unknown")
        ref = f"finding:{fid}"
        text = _finding_text(finding)
        weight = _severity_weight(finding)
        points = 0
        reasons: list[str] = []

        # Anti-debugging techniques
        matched = _match_any(text, _ANTI_DEBUG_WORDS)
        if matched:
            points += int(20 * weight)
            reasons.append(f"Anti-debug technique ({matched[0]})")

        # Anti-VM / sandbox detection
        matched = _match_any(text, _ANTI_VM_WORDS)
        if matched:
            points += int(20 * weight)
            reasons.append(f"Anti-VM detection ({matched[0]})")

        # Timing-based evasion
        matched = _match_any(text, _TIMING_WORDS)
        if matched:
            points += int(15 * weight)
            reasons.append(f"Timing-based evasion ({matched[0]})")

        # Packing / obfuscation
        matched = _match_any(text, _PACKING_WORDS)
        if matched:
            points += int(25 * weight)
            reasons.append(f"Packing / obfuscation ({matched[0].strip()})")

        # High-entropy sections reported as evidence
        entropy_matches = [
            ev_val
            for ev_type, ev_val in _finding_evidence_values(finding)
            if ev_type == "section" and "entropy" in ev_val
        ]
        if entropy_matches:
            points += int(20 * weight)
            reasons.append(f"High-entropy section in evidence: {entropy_matches[0][:60]}")

        if points > 0:
            hits.append(_Hit(points, ref, "; ".join(reasons)))

    return _finalize(hits)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_report(report: dict) -> ThreatScore:
    """Compute deterministic threat scores for a merged SCARABEO report.

    Returns a ThreatScore with per-dimension CategoryScore objects, each
    containing score (0–100), confidence (0–90), and rationale[].

    Raises:
        TypeError: if *report* is not a dict.
    """
    if not isinstance(report, dict):
        raise TypeError(f"report must be a dict, got {type(report).__name__}")

    persistence = _score_persistence(report)
    exfiltration = _score_exfiltration(report)
    stealth = _score_stealth(report)

    # Weighted combination: exfiltration > persistence > stealth
    overall = min(100, int(
        0.40 * exfiltration.score
        + 0.35 * persistence.score
        + 0.25 * stealth.score
    ))

    return ThreatScore(
        persistence=persistence,
        exfiltration=exfiltration,
        stealth=stealth,
        overall=overall,
        sample_sha256=report.get("sample_sha256", ""),
    )
