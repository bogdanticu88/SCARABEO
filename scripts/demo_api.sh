#!/usr/bin/env bash
# SCARABEO API end-to-end demo
#
# Prerequisites:
#   make up          — start PostgreSQL, Redis, MinIO
#   make migrate     — apply DB schema
#   make up-all      — start ingest, worker, orchestrator services
#
# Usage:
#   bash scripts/demo_api.sh [sample_path]
#
# If no sample path is given a small synthetic blob is used.

set -euo pipefail

INGEST_URL="${SCARABEO_INGEST_URL:-http://localhost:8000}"
SEARCH_URL="${SCARABEO_SEARCH_URL:-http://localhost:8002}"
TENANT="${SCARABEO_TENANT:-demo-tenant}"
USER_ID="${SCARABEO_USER:-demo-user}"
ROLE="${SCARABEO_ROLE:-analyst}"
POLL_INTERVAL=3
POLL_MAX=40

# ── Colors ───────────────────────────────────────────────────────────────────

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
DIM="\033[2m"
RESET="\033[0m"

hdr()  { echo -e "\n${BOLD}${CYAN}────────────────────────────────────────────────${RESET}"; \
          echo -e "${BOLD}${CYAN}  $*${RESET}"; \
          echo -e "${BOLD}${CYAN}────────────────────────────────────────────────${RESET}"; }
ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
info() { echo -e "  ${DIM}·${RESET} $*"; }
warn() { echo -e "  ${YELLOW}!${RESET} $*"; }

# ── Common headers ────────────────────────────────────────────────────────────

HEADERS=(
    -H "X-Tenant-Id: ${TENANT}"
    -H "X-User-Id: ${USER_ID}"
    -H "X-Role: ${ROLE}"
)

# ── 0. Health check ───────────────────────────────────────────────────────────

hdr "Step 0 · Service health"

if ! curl -sf "${INGEST_URL}/healthz" > /dev/null; then
    echo -e "  ${YELLOW}Ingest service not reachable at ${INGEST_URL}${RESET}"
    echo -e "  ${DIM}Run: make up-all${RESET}"
    exit 1
fi
ok "Ingest service is up at ${INGEST_URL}"

# ── 1. Prepare sample ─────────────────────────────────────────────────────────

hdr "Step 1 · Prepare sample"

if [[ $# -ge 1 ]]; then
    SAMPLE_PATH="$1"
    ok "Using: ${SAMPLE_PATH}"
else
    SAMPLE_PATH=$(mktemp --suffix=.bin)
    # Synthetic binary with IOC strings
    printf 'MZ\x90\x00' > "${SAMPLE_PATH}"
    printf 'IsDebuggerPresent\x00' >> "${SAMPLE_PATH}"
    printf 'http://192.0.2.47/beacon\x00' >> "${SAMPLE_PATH}"
    printf 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Update\x00' >> "${SAMPLE_PATH}"
    printf 'schtasks /create /tn Updater /tr malware.exe /sc onlogon\x00' >> "${SAMPLE_PATH}"
    printf 'UPX0\x00vmtoolsd.exe\x00' >> "${SAMPLE_PATH}"
    warn "No sample path given — using synthetic blob at ${SAMPLE_PATH}"
fi

FILENAME=$(basename "${SAMPLE_PATH}")
SHA256=$(sha256sum "${SAMPLE_PATH}" | awk '{print $1}')
info "Filename : ${FILENAME}"
info "SHA-256  : ${SHA256}"

# ── 2. Upload ─────────────────────────────────────────────────────────────────

hdr "Step 2 · Upload"

UPLOAD_RESP=$(curl -sf -X POST "${INGEST_URL}/samples" \
    "${HEADERS[@]}" \
    -F "file=@${SAMPLE_PATH};filename=${FILENAME}")

JOB_ID=$(echo "${UPLOAD_RESP}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_id',''))")
ok "Uploaded. Job ID: ${JOB_ID}"

# ── 3. Poll for completion ────────────────────────────────────────────────────

hdr "Step 3 · Poll job status"

STATUS=""
for i in $(seq 1 "${POLL_MAX}"); do
    POLL_RESP=$(curl -sf "${INGEST_URL}/jobs/${JOB_ID}" "${HEADERS[@]}" || true)
    STATUS=$(echo "${POLL_RESP}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "error")
    echo -e "  ${DIM}[${i}/${POLL_MAX}]${RESET} status: ${STATUS}"
    if [[ "${STATUS}" == "completed" || "${STATUS}" == "failed" ]]; then
        break
    fi
    sleep "${POLL_INTERVAL}"
done

if [[ "${STATUS}" != "completed" ]]; then
    warn "Job did not complete within $((POLL_MAX * POLL_INTERVAL))s (final status: ${STATUS})"
    exit 1
fi
ok "Job completed"

# ── 4. Fetch report ───────────────────────────────────────────────────────────

hdr "Step 4 · Fetch analysis report"

REPORT=$(curl -sf "${INGEST_URL}/samples/${SHA256}/report" "${HEADERS[@]}")

VERDICT=$(echo "${REPORT}" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['summary']['verdict'])")
SCORE=$(echo "${REPORT}" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r['summary']['score'])")
FINDING_COUNT=$(echo "${REPORT}" | python3 -c "import sys,json; r=json.load(sys.stdin); print(len(r.get('findings',[])))")
IOC_COUNT=$(echo "${REPORT}" | python3 -c "import sys,json; r=json.load(sys.stdin); print(len(r.get('iocs',[])))")

ok "Verdict  : ${VERDICT}"
info "Score    : ${SCORE}/100"
info "Findings : ${FINDING_COUNT}"
info "IOCs     : ${IOC_COUNT}"

# ── 5. Search ─────────────────────────────────────────────────────────────────

hdr "Step 5 · Search"

if curl -sf "${SEARCH_URL}/healthz" > /dev/null 2>&1; then
    SEARCH_RESP=$(curl -sf "${SEARCH_URL}/search?q=verdict:malicious" "${HEADERS[@]}" || echo '{}')
    TOTAL=$(echo "${SEARCH_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo "?")
    ok "Search (verdict:malicious): ${TOTAL} result(s)"
else
    warn "Search service not reachable — skipping"
fi

# ── 6. AI summary (optional) ──────────────────────────────────────────────────

hdr "Step 6 · AI summary (optional)"

AI_RESP=$(curl -sf "${INGEST_URL}/samples/${SHA256}/ai/summary" "${HEADERS[@]}" 2>/dev/null || true)
if [[ -n "${AI_RESP}" ]]; then
    NARRATIVE=$(echo "${AI_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('narrative','')[:200])" 2>/dev/null || echo "")
    if [[ -n "${NARRATIVE}" ]]; then
        ok "AI narrative:"
        info "${NARRATIVE}"
    else
        warn "AI summary returned no narrative (Ollama may be disabled)"
    fi
else
    warn "AI endpoint not reachable — set OLLAMA_ENABLED=true and start Ollama"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

hdr "Done"
ok "SHA-256 : ${SHA256}"
ok "Verdict : ${VERDICT}  (score ${SCORE})"
ok "Report  : ${INGEST_URL}/samples/${SHA256}/report"

# Cleanup synthetic sample
if [[ $# -lt 1 ]]; then
    rm -f "${SAMPLE_PATH}"
fi
