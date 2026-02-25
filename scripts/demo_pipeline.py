#!/usr/bin/env python3
"""SCARABEO end-to-end demo pipeline.

Demonstrates the full library chain in a single process — no Docker, no
PostgreSQL, no Redis, no Ollama required. Runs on any machine that has the
scarabeo package installed:

    pip install -e .
    python scripts/demo_pipeline.py              # synthetic PE-like sample
    python scripts/demo_pipeline.py malware.exe  # real file (any type)
"""

from __future__ import annotations

import hashlib
import sys as _sys
import pathlib as _pathlib

# Allow running from the repo root without pip install -e .
_ROOT = _pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_ROOT))
import json
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

# ── ANSI helpers ──────────────────────────────────────────────────────────────

_USE_COLOR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

def _hdr(title: str) -> None:
    bar = "─" * 62
    print(f"\n{_c('1;36', bar)}")
    print(_c("1;36", f"  {title}"))
    print(_c("1;36", bar))

def _ok(msg: str)   -> None: print(f"  {_c('32', '✓')} {msg}")
def _info(msg: str) -> None: print(f"  {_c('2', '·')} {msg}")
def _warn(msg: str) -> None: print(f"  {_c('33', '!')} {msg}")
def _kv(key: str, val: str, *, width: int = 22) -> None:
    print(f"  {_c('2', key.ljust(width))}  {val}")

def _block(label: str, data: object) -> None:
    text = json.dumps(data, indent=2) if not isinstance(data, str) else data
    print(f"\n  {_c('33', label + ':')}")
    for line in text.splitlines():
        print(f"    {line}")

# ── Synthetic sample ──────────────────────────────────────────────────────────

_SYNTHETIC = b"\x4d\x5a\x90\x00" + b"\x00" * 56  # MZ header stub
_SYNTHETIC += (
    # Strings with known IOC and evasion indicators
    b"\x00" + b"IsDebuggerPresent\x00"
    b"vmtoolsd.exe\x00"
    b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Update\x00"
    b"http://update.malware-c2.example/beacon\x00"
    b"schtasks /create /tn Updater /tr malware.exe /sc onlogon\x00"
    b"CryptEncrypt\x00"
    b"AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\x00"
    b"192.0.2.47\x00"
    b"UPX0\x00"
)

_SYNTHETIC_IMPORTS = [
    {
        "dll": "kernel32.dll",
        "functions": [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ],
    },
    {
        "dll": "advapi32.dll",
        "functions": ["RegOpenKeyExA", "RegSetValueExA", "CryptEncrypt"],
    },
]

_SYNTHETIC_PE_META = {
    "dll_characteristics": 0x0000,    # no ASLR, no NX
    "subsystem": 2,                   # Windows GUI
    "timestamp": 0,                   # zeroed (anti-forensic)
    "sections": [
        {"name": "UPX0", "characteristics": 0xE0000080,
         "entropy": 7.92, "virtual_size": 0x1000, "raw_size": 0},
        {"name": "UPX1", "characteristics": 0xE0000020,
         "entropy": 7.88, "virtual_size": 0x2000, "raw_size": 0x2000},
    ],
    "imports": _SYNTHETIC_IMPORTS,
}


# ── Main pipeline ─────────────────────────────────────────────────────────────

def main(argv: list[str]) -> None:
    print(_c("1", "\nSCARABEO — end-to-end analysis demo"))
    print(_c("2", "scarabeo.ioc → evasion → scoring → timeline\n"))

    # ── 1. Load sample ────────────────────────────────────────────────────────
    _hdr("Step 1 · Load sample")

    if len(argv) > 1:
        sample_path = Path(argv[1])
        if not sample_path.exists():
            print(f"  Error: {sample_path} not found", file=sys.stderr)
            sys.exit(1)
        data = sample_path.read_bytes()
        label = sample_path.name
    else:
        data = _SYNTHETIC
        label = "synthetic-pe.bin (built-in)"
        _warn("No sample path given — using built-in synthetic PE blob")

    _ok(f"Loaded: {label}  ({len(data):,} bytes)")

    # ── 2. Hash ───────────────────────────────────────────────────────────────
    _hdr("Step 2 · Hash")

    md5    = hashlib.md5(data).hexdigest()
    sha1   = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    _kv("MD5",    md5)
    _kv("SHA-1",  sha1)
    _kv("SHA-256", sha256)

    # ── 3. IOC extraction ─────────────────────────────────────────────────────
    _hdr("Step 3 · IOC extraction")

    from scarabeo.ioc import extract_iocs, make_ioc_records, deduplicate_ioc_records

    # Decode strings from the binary (printable ASCII runs ≥ 6 chars)
    import re
    raw_strings = re.findall(rb"[\x20-\x7e]{6,}", data)
    text_blob   = "\n".join(s.decode("ascii", errors="ignore") for s in raw_strings)

    raw_iocs = extract_iocs(
        text_blob,
        include_private_ips=True,
        include_filepaths=True,
        include_registry=True,
    )

    ioc_records_list: list[dict] = []
    for ioc_type, values in raw_iocs.items():
        recs = make_ioc_records(
            {ioc_type: values},
            first_seen_in=sha256[:16],
            context="static strings",
        )
        ioc_records_list.extend(recs)
    ioc_records_list = deduplicate_ioc_records(ioc_records_list)

    _ok(f"Extracted {len(ioc_records_list)} unique IOCs")
    for rec in ioc_records_list[:8]:
        _info(f"[{rec['type']:10s}] {rec['value'][:60]}")
    if len(ioc_records_list) > 8:
        _info(f"... and {len(ioc_records_list) - 8} more")

    # ── 4. Evasion analysis ───────────────────────────────────────────────────
    _hdr("Step 4 · Evasion analysis")

    from scarabeo.evasion import build_evasion_profile, evasion_profile_to_findings

    string_list = [s.decode("ascii", errors="ignore") for s in raw_strings]
    profile     = build_evasion_profile(
        _SYNTHETIC_IMPORTS if len(argv) == 1 else [],
        string_list,
        _SYNTHETIC_PE_META if len(argv) == 1 else None,
    )

    _ok(f"Evasion score: {profile.score}/100")
    _kv("Breakdown", ", ".join(
        f"{cat}={sc}" for cat, sc in sorted(profile.score_breakdown.items()) if sc > 0
    ))
    _ok(f"Indicators found: {len(profile.indicators)}")
    for ind in profile.indicators[:6]:
        _info(f"  [{ind.category}] {ind.technique} — {', '.join(list(ind.evidence)[:3])}")

    evasion_findings = evasion_profile_to_findings(profile, source="demo-evasion")
    _ok(f"Converted to {len(evasion_findings)} findings")

    # ── 5. Build report dict ──────────────────────────────────────────────────
    _hdr("Step 5 · Assemble analysis report")

    now = datetime.now(timezone.utc).isoformat()

    report = {
        "schema_version": "1.0.0",
        "sample_sha256":  sha256,
        "tenant_id":      "demo",
        "file_type":      "pe",
        "hashes":         {"md5": md5, "sha1": sha1, "sha256": sha256},
        "summary":        {"verdict": "malicious" if profile.score > 50 else "suspicious",
                           "score":   profile.score},
        "findings":       evasion_findings,
        "iocs":           ioc_records_list,
        "artifacts":      [],
        "provenance": {
            "pipeline_name": "demo",
            "pipeline_hash": "0" * 64,
            "engines": [{"name": "demo-evasion", "version": "1.0.0"}],
            "config_hash": "0" * 64,
            "deterministic_run": True,
        },
        "timestamps": {"analysis_start": now, "analysis_end": now},
    }

    _ok(f"Verdict: {_c('1;31', report['summary']['verdict'])}  "
        f"(score {report['summary']['score']})")
    _ok(f"{len(evasion_findings)} findings, {len(ioc_records_list)} IOCs")

    # ── 6. Threat scoring ─────────────────────────────────────────────────────
    _hdr("Step 6 · Evidence-based threat scoring")

    from scarabeo.scoring import score_report

    ts = score_report(report)

    _kv("Persistence",   f"{ts.persistence.score:3d}/100  confidence {ts.persistence.confidence}%")
    _kv("Exfiltration",  f"{ts.exfiltration.score:3d}/100  confidence {ts.exfiltration.confidence}%")
    _kv("Stealth",       f"{ts.stealth.score:3d}/100  confidence {ts.stealth.confidence}%")
    _kv("Overall",       _c("1", f"{ts.overall}/100"))

    print()
    _ok("Rationale (persistence):")
    for r in ts.persistence.rationale[:3]:
        _info("  " + textwrap.shorten(r, 78))

    _ok("Rationale (stealth):")
    for r in ts.stealth.rationale[:3]:
        _info("  " + textwrap.shorten(r, 78))

    # ── 7. Execution timeline ─────────────────────────────────────────────────
    _hdr("Step 7 · Execution timeline reconstruction")

    from scarabeo.timeline import TimelineBuilder

    timeline = TimelineBuilder().build(report)

    _ok(f"Reconstructed {len(timeline.steps)} execution phases")
    _info(f"Generated by: {timeline.generated_by}")
    print()
    for step in timeline.steps:
        phase_label = _c("1;33", f"[{step.phase_label}]")
        confidence  = _c("2", f"confidence {step.confidence}%")
        print(f"  {phase_label}  {step.description}  {confidence}")
        for ref in step.evidence_refs[:2]:
            _info(f"    evidence: {ref}")

    # ── Done ──────────────────────────────────────────────────────────────────
    _hdr("Complete")

    _ok(f"SHA-256:  {sha256}")
    _ok(f"Verdict:  {report['summary']['verdict']}")
    _ok(f"Phases:   {len(timeline.steps)}")
    _ok(f"Threat:   persistence={ts.persistence.score}  "
        f"exfil={ts.exfiltration.score}  stealth={ts.stealth.score}  "
        f"overall={ts.overall}")
    print()


if __name__ == "__main__":
    main(sys.argv)
