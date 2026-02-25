# SCARABEO Roadmap

Milestones are ordered by **impact-to-effort ratio** — each step enables the
next cleanly, avoids rework, and delivers a visible capability increment.

---

## M0.1 — Schema Enforcement ✅

**Why first:** Any data that enters the system without a contract will cause
subtle, hard-to-reproduce bugs later. Schema enforcement is the foundation
everything else relies on. Without it, a single malformed analyzer output can
corrupt the merged report silently.

**Delivered:**
- `scarabeo/validation.py` — runtime validation against JSON schemas using
  `Draft202012Validator`.
- `validate_partial()` called per analyzer output before merge.
- `validate_report()` called on assembled report before storage.
- Fail-closed: schema violations abort the job and mark it `FAILED`.
- 14 unit tests in `tests/test_schema_validation.py`.

---

## M0.2 — Normalized Data Model ⬜

**Why second:** The normalized model is the single source of truth for all
downstream features — memory store, similarity, AI explanation, scoring, and
timeline all consume it. Changing it later requires migrating everything.

**Planned scope:**
- Extend `Finding`, `IOC`, and `Artifact` schemas with stable, typed fields
  that all analyzers agree on (e.g. `mitre_technique_id`, `cvss_score`,
  `ioc_confidence_source`).
- Add `SampleProfile` — a denormalized, indexed view of a report used for
  fast similarity and memory lookups.
- Introduce a `NormalizedReport` dataclass in `scarabeo/models.py` with
  factory methods and field-level validation.
- Schema migration tooling (`alembic` revisions for `SampleProfile` table).

**Unlocks:** M3 (memory/similarity requires a stable profile representation),
M4 (AI context is richer when findings have MITRE IDs and structured evidence).

---

## M1 — PE Analyzer + Evasion + IOC Library ✅

**Delivered:**
- `scarabeo/evasion.py` — import-table, string, and PE-metadata heuristics
  across anti-debug, anti-VM, anti-sandbox, injection, packer, and
  persistence categories. 100-point scoring with per-category breakdown.
- `scarabeo/ioc.py` — IOC extraction (URL, IP, domain, email, filepath,
  registry), normalization, deduplication, and `make_ioc_records()` for
  schema-compliant output.
- `analyzers/pe-analyzer/` — containerized PE analysis engine.
- `analyzers/triage-universal/` — generic strings + entropy + IOC pass.
- Combined: 742 passing tests, full schema compliance.

---

## M2 — Evidence-Based Threat Scoring + Execution Timeline ✅

**Delivered:**
- `scarabeo/scoring.py` — deterministic three-dimension scoring:
  persistence, exfiltration, stealth. Each score is 0–100 with a
  `rationale[]` list that references specific evidence IDs.
  Confidence tracks distinct source count, not raw hit count.
- `scarabeo/timeline.py` — rules-based execution phase reconstruction
  (10 phases, `IntEnum`-ordered). Optional AI narrative rewrite via any
  `ExplainerProvider`; rewrite cannot change step order, count, or evidence.
- `scripts/demo_pipeline.py` — runnable end-to-end demo that chains
  IOC extraction → evasion analysis → scoring → timeline without
  needing any running service.

---

## M3 — Memory Store + Similarity Enrichment ⬜

**Why here:** With a normalized data model (M0.2) in place, similarity
becomes a one-pass operation. This is the primary capability differentiator:
analysts stop looking at samples in isolation and start seeing clusters,
campaign attribution, and code reuse patterns.

**Planned scope:**
- `scarabeo/memory.py` — persistent `SampleProfile` store backed by
  PostgreSQL. Upsert on every completed analysis job.
- Similarity scoring: TLSH (byte-level), SSDEEP (string-level), imphash
  (import table), strings-hash (semantic). Each stored as a column on
  `SampleProfile`.
- `find_similar(sha256, tenant_id, *, algorithm, threshold, limit)` — query
  returns ranked matches with per-algorithm distance metrics.
- Enrichment step in `services/worker/processor.py`: after report assembly,
  call `enrich_with_similar()` to append a `similar_samples[]` list to the
  report's `summary` block.
- `GET /samples/{sha256}/similar` — new ingest API endpoint.
- Cluster auto-detection: samples with TLSH distance < 30 are grouped into
  a cluster automatically; cluster label is the SHA-256 of the earliest member.
- 20+ unit tests (no DB required — SQLite in-memory for test fixtures).

**Unlocks:** M4 (AI explanation is more useful when it has cluster context).

---

## M4 — AI Explanation Layer ✅

**Why last in the core sequence:** AI explanation is purely additive. It adds
narrative context to an already-complete, already-validated, already-scored
analysis. Being downstream means a bug in the AI layer cannot corrupt the
core report — the job still completes and the report is still valid.

**Delivered:**
- `scarabeo/explain.py` — `FindingExplainer` with `OllamaExplainerProvider`.
  Strict JSON output schema (5 required fields). Three-candidate JSON
  extraction. Fail-open: returns `None` on any error so the job continues.
- `LocalEndpointViolation` guardrail — non-loopback Ollama endpoints are
  rejected at construction time (see `docs/hardening.md`).
- `scarabeo/ai.py` + `scarabeo/llm.py` — free-text narrative, remediation,
  and per-finding explanation generation via `OllamaClient`.
- Three ingest API endpoints: `GET /ai/summary`, `POST /ai/explain`,
  `POST /ai/remediation`. All serve cached results from the report when
  available, generate fresh output when Ollama is reachable, or return 503.
- 43 unit tests in `tests/test_explain.py`. 15 tests in `tests/test_ai.py`.

---

## Suggested Implementation Order

For contributors picking up M0.2 or M3:

```
M0.2 Normalized model
  → adds SampleProfile schema and migration
  → update existing test fixtures to use NormalizedReport

M3 Memory + similarity
  → upsert SampleProfile on every completed job
  → implement find_similar()
  → add /samples/{sha256}/similar endpoint
  → add cluster auto-detection

M4 AI context enrichment (extend existing)
  → pass similar_samples[] and cluster_id into FindingExplainer prompt
  → update EXPLANATION_JSON_SCHEMA to include optional cluster_context field
```

---

## Version History

| Version | Milestone | Status |
|---------|-----------|--------|
| 1.0.0 | M0.1 + M1 + M2 + M4 | Released |
| 1.1.0 | M0.2 Normalized model | Planned |
| 1.2.0 | M3 Memory + similarity | Planned |
| 1.3.0 | M4 AI context enrichment (extend) | Planned |
