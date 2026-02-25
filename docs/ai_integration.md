# AI Integration

SCARABEO can optionally enrich analysis reports with AI-generated narratives,
remediation advice, and per-finding explanations using a locally-running
[Ollama](https://ollama.com) instance. Everything runs on-premises — no cloud
API keys, no data leaving your environment.

---

## Prerequisites

1. Install Ollama: https://ollama.com/download
2. Pull the default model:
   ```bash
   ollama pull mistral:7b
   ```
3. Verify it is running:
   ```bash
   curl http://localhost:11434/api/tags
   ```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_ENABLED` | `false` | Auto-enrich reports after analysis (worker) |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama base URL |
| `OLLAMA_MODEL` | `mistral:7b` | Model to use for generation |
| `OLLAMA_TIMEOUT` | `120` | Per-request timeout in seconds |

These apply to both the **worker** service (auto-enrichment) and the **ingest**
service (on-demand API endpoints).

---

## How Automatic Enrichment Works

When `OLLAMA_ENABLED=true`, the worker generates a narrative summary and
remediation advice immediately after merging analyzer outputs, before storing
the report. The result is stored under the `ai_analysis` key in the report JSON.

If Ollama is unreachable at that moment, the worker logs a warning and continues
— the job still succeeds, just without `ai_analysis`. This is intentional
fail-open behaviour.

```bash
OLLAMA_ENABLED=true python -m services.worker
```

---

## On-Demand API Endpoints

All three endpoints require the standard `X-Tenant-Id` and `X-Role` headers.
They work regardless of `OLLAMA_ENABLED` — as long as Ollama is reachable.
If Ollama is down and there is no cached result, the endpoints return `503`.

### GET /samples/{sha256}/ai/summary

Returns the executive narrative summary. If `ai_analysis` is already cached in
the stored report, it is returned immediately (`cached: true`) without calling
Ollama.

```bash
curl http://localhost:8000/samples/{sha256}/ai/summary \
  -H "X-Tenant-Id: demo" \
  -H "X-Role: analyst"
```

**Response:**
```json
{
  "sha256": "abc123...",
  "narrative": "This PE32 executable was classified as malicious with a risk score of 87/100. Analysis revealed process injection capability via VirtualAllocEx and evidence of packing...",
  "remediation": null,
  "generated_at": "2024-01-15T10:10:00+00:00",
  "model": "mistral:7b",
  "cached": false
}
```

---

### POST /samples/{sha256}/ai/explain

Generate a plain-English explanation for a specific finding. Always calls
Ollama — explanations are never cached.

```bash
curl -X POST http://localhost:8000/samples/{sha256}/ai/explain \
  -H "X-Tenant-Id: demo" \
  -H "X-Role: analyst" \
  -H "Content-Type: application/json" \
  -d '{"finding_id": "f-001"}'
```

**Response:**
```json
{
  "finding_id": "f-001",
  "explanation": "VirtualAllocEx is a Windows API function that allocates memory in the address space of another process. Malware commonly uses this function as the first step in process injection (MITRE ATT&CK T1055), allowing it to execute arbitrary code within a trusted process...",
  "model": "mistral:7b"
}
```

---

### POST /samples/{sha256}/ai/remediation

Return remediation advice. Returns cached advice if the report already contains
it, otherwise generates fresh output.

```bash
curl -X POST http://localhost:8000/samples/{sha256}/ai/remediation \
  -H "X-Tenant-Id: demo" \
  -H "X-Role: analyst"
```

**Response:**
```json
{
  "sha256": "abc123...",
  "narrative": null,
  "remediation": "1. Isolate the affected host immediately...\n2. Block outbound connections to 192.0.2.1 and evil.example.com...\n3. Search SIEM for process creation events where parent is explorer.exe...",
  "generated_at": "2024-01-15T10:11:00+00:00",
  "model": "mistral:7b",
  "cached": false
}
```

---

## Swapping Models

Any model available in your Ollama instance can be used. Set `OLLAMA_MODEL` to
the desired model tag:

```bash
# Use Mistral Nemo (12B, higher quality)
OLLAMA_MODEL=mistral-nemo ollama pull mistral-nemo

# Use Codestral (code-optimised)
OLLAMA_MODEL=codestral ollama pull codestral

# Use Llama 3 (8B)
OLLAMA_MODEL=llama3 ollama pull llama3
```

Larger models produce better output at the cost of higher latency. Adjust
`OLLAMA_TIMEOUT` accordingly for models that take longer to respond.

---

## Running Tests

The unit tests are fully mocked — no Ollama instance required:

```bash
pytest tests/test_ai.py -v
```

To run the full suite and confirm no regressions:

```bash
pytest tests/ -q --tb=no
```
