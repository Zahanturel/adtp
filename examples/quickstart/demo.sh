#!/usr/bin/env bash
# ADTP quickstart demo — runs the full lifecycle in ~10 curl commands.
# Usage: ADTP_API_KEY=<key> bash demo.sh
set -euo pipefail

BASE="${ADTP_URL:-http://localhost:8080}"
KEY="${ADTP_API_KEY:?Set ADTP_API_KEY first}"

auth() { curl -s -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" "$@"; }

echo "=== ADTP Quickstart Demo ==="
echo ""

# Health check
echo "1. Health check"
auth "$BASE/health" | jq .
echo ""

# Register two agents
echo "2. Register orchestrator agent"
AGENT_A=$(auth -X POST "$BASE/v1/agents" -d '{"sponsor_did":"demo@example.com"}' | jq -r .did)
echo "   DID: ${AGENT_A:0:50}..."

echo "3. Register sub-agent"
AGENT_B=$(auth -X POST "$BASE/v1/agents" -d '{"sponsor_did":"demo@example.com"}' | jq -r .did)
echo "   DID: ${AGENT_B:0:50}..."
echo ""

# Issue root credential
echo "4. Issue root credential to orchestrator"
ROOT_CID=$(auth -X POST "$BASE/v1/credentials" \
  -d "{\"agent_did\":\"$AGENT_A\",\"capabilities\":[{\"can\":\"tool/invoke\",\"with\":\"tool://search/*\"},{\"can\":\"agent/delegate\",\"with\":\"tool://search/*\",\"constraints\":[{\"type\":\"delegation_depth\",\"max\":3}]}],\"exp_seconds\":3600}" \
  | jq -r .cid)
echo "   CID: ${ROOT_CID:0:50}..."
echo ""

# Delegate with RESTRICT
NOW=$(date +%s)
START=$((NOW - 60))
END=$((NOW + 1800))
echo "5. Delegate to sub-agent (RESTRICT mode, 30min window)"
DEL_CID=$(auth -X POST "$BASE/v1/delegations" \
  -d "{\"parent_cid\":\"$ROOT_CID\",\"audience_did\":\"$AGENT_B\",\"mode\":\"restrict\",\"depth_left\":2,\"caveats\":[{\"type\":\"resource_restrict\",\"resource\":\"tool://search/web\"},{\"type\":\"time_window\",\"start\":$START,\"end\":$END}]}" \
  | jq -r .cid)
echo "   CID: ${DEL_CID:0:50}..."
echo ""

# Verify — authorized
echo "6. Verify tool://search/web (should pass)"
auth -X POST "$BASE/v1/verify" \
  -d "{\"chain\":[\"$DEL_CID\"],\"action\":\"tool/invoke\",\"resource\":\"tool://search/web\"}" | jq '{authorized, chain_depth}'
echo ""

# Verify — denied (wrong resource)
echo "7. Verify tool://search/internal (should be denied)"
auth -X POST "$BASE/v1/verify" \
  -d "{\"chain\":[\"$DEL_CID\"],\"action\":\"tool/invoke\",\"resource\":\"tool://search/internal\"}" | jq '{authorized, error_code}'
echo ""

# Revoke
echo "8. Revoke root credential (cascade)"
auth -X POST "$BASE/v1/revoke" \
  -d "{\"subject_cid\":\"$ROOT_CID\",\"scope\":\"subtree\",\"status\":\"COMPROMISED\"}" | jq '{seq, cascade_count}'
echo ""

# Verify after revocation
echo "9. Verify after revocation (should be denied)"
auth -X POST "$BASE/v1/verify" \
  -d "{\"chain\":[\"$DEL_CID\"],\"action\":\"tool/invoke\",\"resource\":\"tool://search/web\"}" | jq '{authorized, error_code}'
echo ""

echo "=== Done ==="
