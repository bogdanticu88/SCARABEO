"""
Deterministic execution timeline reconstruction for SCARABEO analysis reports.

Maps normalized findings, IOCs, evasion indicators, imported API names, and
artifacts into an ordered sequence of likely execution phases using a
rules-based engine.  No AI dependency — a Timeline is always produced when
sufficient evidence exists.

Optional AI narrative rewrite
------------------------------
``rewrite_timeline_with_ai()`` accepts any provider with a
``complete(prompt: str) -> str`` method (e.g. OllamaExplainerProvider).
The AI may only rewrite step *descriptions* as plain narrative.  It cannot
reorder steps, add steps without evidence_refs, or alter evidence_refs —
those invariants are enforced structurally after the response is parsed.
If the response is invalid or the provider fails, the original rules-based
timeline is returned unchanged.
"""

import json
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from jsonschema import Draft202012Validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Phase ordering
# ---------------------------------------------------------------------------

class Phase(IntEnum):
    """
    Execution phases in ascending order.  IntEnum guarantees that
    ``steps.sort(key=lambda s: s.phase)`` is always deterministic.
    """
    INITIAL_LOAD         = 0
    ANTI_ANALYSIS        = 1
    UNPACKING            = 2
    PROCESS_INJECTION    = 3
    PRIVILEGE_ESCALATION = 4
    PERSISTENCE          = 5
    LATERAL_MOVEMENT     = 6
    C2_COMMUNICATION     = 7
    DATA_COLLECTION      = 8
    PAYLOAD_EXECUTION    = 9


PHASE_LABELS: dict[Phase, str] = {
    Phase.INITIAL_LOAD:          "Initial Load",
    Phase.ANTI_ANALYSIS:         "Anti-Analysis / Evasion",
    Phase.UNPACKING:             "Unpacking / Decryption",
    Phase.PROCESS_INJECTION:     "Process Injection",
    Phase.PRIVILEGE_ESCALATION:  "Privilege Escalation",
    Phase.PERSISTENCE:           "Persistence",
    Phase.LATERAL_MOVEMENT:      "Lateral Movement",
    Phase.C2_COMMUNICATION:      "Command & Control",
    Phase.DATA_COLLECTION:       "Data Collection",
    Phase.PAYLOAD_EXECUTION:     "Payload Execution",
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class TimelineStep:
    """A single step in the reconstructed execution timeline."""
    phase: Phase
    phase_label: str
    description: str
    evidence_refs: list[str]   # "finding:{id}", "ioc:{type}:{value}", "artifact:{path}"
    confidence: int            # 0–100, derived from matched finding confidences


@dataclass
class Timeline:
    """Ordered execution timeline reconstructed from a SCARABEO report."""
    file_type: str
    steps: list[TimelineStep]  # sorted ascending by Phase value
    generated_by: str = "rules"  # "rules" | "rules+ai"

    def is_empty(self) -> bool:
        return len(self.steps) == 0


# ---------------------------------------------------------------------------
# Internal analysis context
# ---------------------------------------------------------------------------

@dataclass
class _Context:
    findings: list[dict]
    iocs: list[dict]
    artifacts: list[dict]
    file_type: str


def _build_context(report: dict) -> _Context:
    return _Context(
        findings=report.get("findings", []),
        iocs=report.get("iocs", []),
        artifacts=report.get("artifacts", []),
        file_type=report.get("file_type", "unknown"),
    )


# ---------------------------------------------------------------------------
# Evidence reference helpers
# ---------------------------------------------------------------------------

def _finding_ref(f: dict) -> str:
    return f"finding:{f['id']}"


def _ioc_ref(ioc: dict) -> str:
    return f"ioc:{ioc['type']}:{ioc['value']}"


def _artifact_ref(a: dict) -> str:
    return f"artifact:{a['path']}"


# ---------------------------------------------------------------------------
# Keyword matching helpers
# ---------------------------------------------------------------------------

def _text_has_any(text: str, keywords: frozenset[str]) -> bool:
    t = text.lower()
    return any(kw in t for kw in keywords)


def _finding_matches(f: dict, keywords: frozenset[str]) -> bool:
    """True if any keyword appears in title, description, tags, or evidence values."""
    return (
        _text_has_any(f.get("title", ""), keywords)
        or _text_has_any(f.get("description", ""), keywords)
        or any(_text_has_any(t, keywords) for t in f.get("tags", []))
        or any(_text_has_any(ev.get("value", ""), keywords) for ev in f.get("evidence", []))
    )


def _match_findings(findings: list[dict], keywords: frozenset[str]) -> list[dict]:
    return [f for f in findings if _finding_matches(f, keywords)]


def _match_iocs(iocs: list[dict], *types: str) -> list[dict]:
    return [ioc for ioc in iocs if ioc.get("type") in types]


def _confidence_from(matched: list[dict], base: int = 60) -> int:
    """Average confidence of matched findings, clamped to [0, 100]."""
    vals = [f["confidence"] for f in matched if "confidence" in f]
    if not vals:
        return base
    return max(0, min(100, sum(vals) // len(vals)))


# ---------------------------------------------------------------------------
# Rule implementations
# (one function per phase; each returns TimelineStep | None)
# ---------------------------------------------------------------------------

_KW_HEADER = frozenset({
    "pe header", "dos header", "nt header", "sections mapped",
    "entry point", "coff", "pe32", "portable executable",
})

_KW_DEBUGGER = frozenset({
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "outputdebugstring", "debugbreak", "findwindow", "anti-debug", "antidebug",
    "debugger", "timing check", "rdtsc", "anti-analysis",
})

_KW_SANDBOX = frozenset({
    "vmware", "virtualbox", "vbox", "virtual machine", "sandbox",
    "cpuid", "hypervisor", "red pill", "vm detect", "sleep evasion",
})

_KW_OBFUSCATION = frozenset({
    "loadlibrary", "getprocaddress", "dynamic api", "obfuscat",
    "string decryption", "api hashing", "api resolve",
})

_KW_UNPACK = frozenset({
    "virtualalloc", "virtualprotect", "high entropy", "upx", "themida",
    "aspack", "packed", "self-modifying", "reflective load", "heap spray",
    "decrypt stub", "unpacking",
})

_KW_INJECT = frozenset({
    "virtualallocex", "writeprocessmemory", "createremotethread",
    "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc",
    "ntunmapviewofsection", "zwunmapviewofsection",
    "process hollow", "process injection", "dll injection", "reflective dll",
})

_KW_PRIVESC = frozenset({
    "impersonateloggedonuser", "duplicatetoken", "adjusttokenprivileges",
    "sedebuggerprivilege", "uac bypass", "elevat", "privilege escalation",
    "token impersonation",
})

_KW_PERSIST_FINDING = frozenset({
    "currentversion\\run", "run key", "registry persistence",
    "createservice", "openscmanager", "scheduled task", "taskscheduler",
    "schtasks", "startup folder", "persistence", "autorun",
})

_KW_LATERAL = frozenset({
    "wmi", "iwbemservices", "lateral movement", "psexec",
    "net use", "admin$", "ipc$", "smb", "wbem",
})

_KW_NETWORK = frozenset({
    "internetopen", "internetopenurl", "internetreadfile",
    "winhttpopen", "winhttpsendrequest",
    "wsastartup", "rawsocket", "dns", "dnsquery", "dnsquerya",
    "network beacon", "c2 communication", "http request",
    "download", "connect", "recv", "send",
})

_KW_COLLECT = frozenset({
    "setwindowshookex", "keylog", "keyboard hook",
    "bitblt", "getdc", "screenshot", "screencapture",
    "credential", "sam database", "ntds.dit", "clipboard",
})

_KW_PAYLOAD = frozenset({
    "createprocess", "shellexecute", "shellexecuteex",
    "winexec", "dropped file", "shellcode", "child process", "execute payload",
})


def _rule_initial_load(ctx: _Context) -> Optional[TimelineStep]:
    is_pe = "pe" in ctx.file_type.lower()
    header_matches = _match_findings(ctx.findings, _KW_HEADER)
    refs = [_finding_ref(f) for f in header_matches]

    if is_pe and not refs:
        refs = ["file_type:pe"]  # file_type is itself sufficient evidence for PE

    if not refs:
        return None

    confidence = _confidence_from(header_matches, base=95 if is_pe else 70)
    desc = (
        "PE image mapped into memory; DOS/NT headers parsed, sections laid out."
        if is_pe
        else f"{ctx.file_type} file loaded for execution."
    )
    return TimelineStep(
        phase=Phase.INITIAL_LOAD,
        phase_label=PHASE_LABELS[Phase.INITIAL_LOAD],
        description=desc,
        evidence_refs=refs,
        confidence=confidence,
    )


def _rule_anti_analysis(ctx: _Context) -> Optional[TimelineStep]:
    debug_m   = _match_findings(ctx.findings, _KW_DEBUGGER)
    sandbox_m = _match_findings(ctx.findings, _KW_SANDBOX)
    obfusc_m  = _match_findings(ctx.findings, _KW_OBFUSCATION)
    all_m = debug_m + sandbox_m + obfusc_m

    # Deduplicate (a finding may match multiple keyword sets)
    seen: set[str] = set()
    deduped = []
    for f in all_m:
        if f["id"] not in seen:
            seen.add(f["id"])
            deduped.append(f)

    if not deduped:
        return None

    refs = [_finding_ref(f) for f in deduped]
    techniques = (
        (["debugger detection"] if debug_m else [])
        + (["VM/sandbox detection"] if sandbox_m else [])
        + (["API obfuscation / dynamic loading"] if obfusc_m else [])
    )
    desc = f"Anti-analysis checks: {', '.join(techniques)}."
    return TimelineStep(
        phase=Phase.ANTI_ANALYSIS,
        phase_label=PHASE_LABELS[Phase.ANTI_ANALYSIS],
        description=desc,
        evidence_refs=refs,
        confidence=_confidence_from(deduped),
    )


def _rule_unpacking(ctx: _Context) -> Optional[TimelineStep]:
    matched = _match_findings(ctx.findings, _KW_UNPACK)
    if not matched:
        return None
    return TimelineStep(
        phase=Phase.UNPACKING,
        phase_label=PHASE_LABELS[Phase.UNPACKING],
        description=(
            "In-memory unpacking/decryption routine active; "
            "executable regions allocated and overwritten before entry point transfer."
        ),
        evidence_refs=[_finding_ref(f) for f in matched],
        confidence=_confidence_from(matched),
    )


def _rule_process_injection(ctx: _Context) -> Optional[TimelineStep]:
    matched = _match_findings(ctx.findings, _KW_INJECT)
    if not matched:
        return None

    techniques: list[str] = []
    if _match_findings(ctx.findings, frozenset({"virtualallocex", "writeprocessmemory", "createremotethread"})):
        techniques.append("classic remote thread injection")
    if _match_findings(ctx.findings, frozenset({"ntunmapviewofsection", "zwunmapviewofsection", "process hollow"})):
        techniques.append("process hollowing")
    if _match_findings(ctx.findings, frozenset({"queueuserapc"})):
        techniques.append("APC injection")
    if _match_findings(ctx.findings, frozenset({"reflective dll"})):
        techniques.append("reflective DLL loading")

    body = ", ".join(techniques) if techniques else "injection technique identified"
    return TimelineStep(
        phase=Phase.PROCESS_INJECTION,
        phase_label=PHASE_LABELS[Phase.PROCESS_INJECTION],
        description=f"Process injection: {body}.",
        evidence_refs=[_finding_ref(f) for f in matched],
        confidence=_confidence_from(matched),
    )


def _rule_privilege_escalation(ctx: _Context) -> Optional[TimelineStep]:
    matched = _match_findings(ctx.findings, _KW_PRIVESC)
    if not matched:
        return None
    return TimelineStep(
        phase=Phase.PRIVILEGE_ESCALATION,
        phase_label=PHASE_LABELS[Phase.PRIVILEGE_ESCALATION],
        description="Privilege escalation attempted via token manipulation or UAC bypass.",
        evidence_refs=[_finding_ref(f) for f in matched],
        confidence=_confidence_from(matched),
    )


def _rule_persistence(ctx: _Context) -> Optional[TimelineStep]:
    finding_m   = _match_findings(ctx.findings, _KW_PERSIST_FINDING)
    registry_iocs = _match_iocs(ctx.iocs, "registry")
    if not finding_m and not registry_iocs:
        return None

    refs = [_finding_ref(f) for f in finding_m] + [_ioc_ref(i) for i in registry_iocs]

    mechanisms: list[str] = []
    if _match_findings(ctx.findings, frozenset({"run key", "currentversion\\run", "registry persistence"})) or registry_iocs:
        mechanisms.append("registry run key")
    if _match_findings(ctx.findings, frozenset({"createservice", "openscmanager"})):
        mechanisms.append("service installation")
    if _match_findings(ctx.findings, frozenset({"scheduled task", "taskscheduler", "schtasks"})):
        mechanisms.append("scheduled task")
    if _match_findings(ctx.findings, frozenset({"startup folder"})):
        mechanisms.append("startup folder")

    body = ", ".join(mechanisms) if mechanisms else "persistence mechanism"
    return TimelineStep(
        phase=Phase.PERSISTENCE,
        phase_label=PHASE_LABELS[Phase.PERSISTENCE],
        description=f"Persistence established via {body}.",
        evidence_refs=refs,
        confidence=_confidence_from(finding_m, base=70),
    )


def _rule_lateral_movement(ctx: _Context) -> Optional[TimelineStep]:
    matched = _match_findings(ctx.findings, _KW_LATERAL)
    if not matched:
        return None
    return TimelineStep(
        phase=Phase.LATERAL_MOVEMENT,
        phase_label=PHASE_LABELS[Phase.LATERAL_MOVEMENT],
        description="Lateral movement capability detected (WMI, SMB, or remote execution APIs).",
        evidence_refs=[_finding_ref(f) for f in matched],
        confidence=_confidence_from(matched),
    )


def _rule_c2_communication(ctx: _Context) -> Optional[TimelineStep]:
    finding_m   = _match_findings(ctx.findings, _KW_NETWORK)
    network_iocs = _match_iocs(ctx.iocs, "ip", "domain", "url")
    if not finding_m and not network_iocs:
        return None

    refs = [_finding_ref(f) for f in finding_m] + [_ioc_ref(i) for i in network_iocs]

    channels: list[str] = []
    if _match_findings(ctx.findings, frozenset({"internetopen", "winhttpopen", "http request"})):
        channels.append("HTTP/HTTPS")
    if _match_findings(ctx.findings, frozenset({"wsastartup", "rawsocket"})):
        channels.append("raw socket")
    if _match_findings(ctx.findings, frozenset({"dnsquery", "dnsquerya", "dns"})) or _match_iocs(ctx.iocs, "domain"):
        channels.append("DNS")
    if network_iocs:
        ioc_summary = ", ".join(f"{i['type']}:{i['value']}" for i in network_iocs[:3])
        if len(network_iocs) > 3:
            ioc_summary += f" (+{len(network_iocs) - 3} more)"
        channels.append(f"IOCs [{ioc_summary}]")

    body = "; ".join(channels) if channels else "network communication"
    return TimelineStep(
        phase=Phase.C2_COMMUNICATION,
        phase_label=PHASE_LABELS[Phase.C2_COMMUNICATION],
        description=f"C2 communication via {body}.",
        evidence_refs=refs,
        confidence=_confidence_from(finding_m, base=75),
    )


def _rule_data_collection(ctx: _Context) -> Optional[TimelineStep]:
    matched = _match_findings(ctx.findings, _KW_COLLECT)
    if not matched:
        return None

    techniques: list[str] = []
    if _match_findings(ctx.findings, frozenset({"setwindowshookex", "keylog", "keyboard hook"})):
        techniques.append("keylogging")
    if _match_findings(ctx.findings, frozenset({"bitblt", "getdc", "screenshot"})):
        techniques.append("screen capture")
    if _match_findings(ctx.findings, frozenset({"credential", "sam database", "ntds.dit"})):
        techniques.append("credential harvesting")
    if _match_findings(ctx.findings, frozenset({"clipboard"})):
        techniques.append("clipboard access")

    body = ", ".join(techniques) if techniques else "data collection"
    return TimelineStep(
        phase=Phase.DATA_COLLECTION,
        phase_label=PHASE_LABELS[Phase.DATA_COLLECTION],
        description=f"Data collection: {body}.",
        evidence_refs=[_finding_ref(f) for f in matched],
        confidence=_confidence_from(matched),
    )


def _rule_payload_execution(ctx: _Context) -> Optional[TimelineStep]:
    finding_m = _match_findings(ctx.findings, _KW_PAYLOAD)
    artifact_m = [a for a in ctx.artifacts if a.get("type") in {"dropped_file", "shellcode", "extracted_pe"}]
    if not finding_m and not artifact_m:
        return None

    refs = [_finding_ref(f) for f in finding_m] + [_artifact_ref(a) for a in artifact_m]

    techniques: list[str] = []
    if _match_findings(ctx.findings, frozenset({"createprocess", "shellexecute", "winexec"})):
        techniques.append("spawning child process")
    if _match_findings(ctx.findings, frozenset({"shellcode"})):
        techniques.append("shellcode execution")
    if artifact_m:
        techniques.append(f"dropped artefact ({len(artifact_m)})")

    body = ", ".join(techniques) if techniques else "payload execution"
    return TimelineStep(
        phase=Phase.PAYLOAD_EXECUTION,
        phase_label=PHASE_LABELS[Phase.PAYLOAD_EXECUTION],
        description=f"Payload delivered: {body}.",
        evidence_refs=refs,
        confidence=_confidence_from(finding_m, base=65),
    )


# ---------------------------------------------------------------------------
# Rule registry (order here is irrelevant — steps are sorted by Phase)
# ---------------------------------------------------------------------------

_RULES = [
    _rule_initial_load,
    _rule_anti_analysis,
    _rule_unpacking,
    _rule_process_injection,
    _rule_privilege_escalation,
    _rule_persistence,
    _rule_lateral_movement,
    _rule_c2_communication,
    _rule_data_collection,
    _rule_payload_execution,
]


# ---------------------------------------------------------------------------
# Timeline builder
# ---------------------------------------------------------------------------

class TimelineBuilder:
    """
    Builds a deterministic Timeline from a SCARABEO report dict.

    Rules fire independently and are sorted by Phase value after collection,
    so the output order is stable regardless of finding input order.
    """

    def build(self, report: dict) -> Timeline:
        ctx = _build_context(report)
        steps: list[TimelineStep] = []

        for rule in _RULES:
            step = rule(ctx)
            if step is not None:
                steps.append(step)

        # Phase is an IntEnum — sort is stable and deterministic
        steps.sort(key=lambda s: s.phase)

        return Timeline(
            file_type=ctx.file_type,
            steps=steps,
            generated_by="rules",
        )


# ---------------------------------------------------------------------------
# Optional AI narrative rewrite
# ---------------------------------------------------------------------------

# JSON schema for the AI response
_REWRITE_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["narratives"],
    "properties": {
        "narratives": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
        },
    },
}
_REWRITE_VALIDATOR = Draft202012Validator(_REWRITE_SCHEMA)


def _build_rewrite_prompt(steps: list[TimelineStep]) -> str:
    payload = json.dumps(
        [
            {
                "step_index": i,
                "phase": s.phase_label,
                "description": s.description,
                "evidence_refs": s.evidence_refs,
                "confidence": s.confidence,
            }
            for i, s in enumerate(steps)
        ],
        indent=2,
    )
    return (
        "You are a malware analyst writing an incident report. "
        "Rewrite each of the following execution timeline steps as a clear, "
        "one-sentence narrative. "
        "Produce exactly one narrative per step, in the same order. "
        "Do not add claims that are not supported by the evidence_refs. "
        "Do not merge or split steps.\n\n"
        f"Steps:\n{payload}\n\n"
        'Respond ONLY with: {"narratives": ["<step 0>", "<step 1>", ...]}\n'
        "No preamble, no markdown fences, no trailing text."
    )


def rewrite_timeline_with_ai(timeline: Timeline, provider) -> Timeline:
    """
    Rewrite timeline step descriptions as AI-generated narrative.

    *provider* must have a ``complete(prompt: str) -> str`` method
    (e.g. ``OllamaExplainerProvider`` from ``scarabeo.explain``).

    Invariants enforced after the AI response is parsed:
    - Step count must equal the input count.
    - Phase ordering is preserved (steps are not re-sorted; they retain
      their original Phase values from the rules pass).
    - evidence_refs are copied unchanged from the original steps.
    - generated_by is set to "rules+ai".

    If any invariant is violated, or if the provider/JSON fails, the
    original timeline is returned unchanged.
    """
    if timeline.is_empty():
        return timeline

    try:
        raw = provider.complete(_build_rewrite_prompt(timeline.steps))
    except Exception as exc:
        logger.warning(f"AI timeline rewrite: provider error — {exc}")
        return timeline

    # Extract first {...} span
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end <= start:
        logger.warning("AI timeline rewrite: no JSON object in response")
        return timeline

    try:
        parsed = json.loads(raw[start : end + 1])
    except json.JSONDecodeError as exc:
        logger.warning(f"AI timeline rewrite: JSON decode error — {exc}")
        return timeline

    errors = list(_REWRITE_VALIDATOR.iter_errors(parsed))
    if errors:
        logger.warning(f"AI timeline rewrite: schema error — {errors[0].message}")
        return timeline

    narratives: list[str] = parsed["narratives"]
    if len(narratives) != len(timeline.steps):
        logger.warning(
            f"AI timeline rewrite: expected {len(timeline.steps)} narratives, "
            f"got {len(narratives)} — discarding"
        )
        return timeline

    new_steps = [
        TimelineStep(
            phase=orig.phase,
            phase_label=orig.phase_label,
            description=narrative,
            evidence_refs=orig.evidence_refs,   # never modified by AI
            confidence=orig.confidence,         # never modified by AI
        )
        for orig, narrative in zip(timeline.steps, narratives)
    ]

    return Timeline(
        file_type=timeline.file_type,
        steps=new_steps,
        generated_by="rules+ai",
    )
