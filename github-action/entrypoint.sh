#!/usr/bin/env bash
set -euo pipefail

# ── Haldir GitHub Action — Create a governed agent session ──

BASE_URL="${HALDIR_BASE_URL:-https://haldir.xyz}"
API_KEY="${HALDIR_API_KEY:?HALDIR_API_KEY is required}"
AGENT_ID="${HALDIR_AGENT_ID:-ci-pipeline}"
SCOPES_CSV="${HALDIR_SCOPES:-read,execute}"
SPEND_LIMIT="${HALDIR_SPEND_LIMIT:-}"
TTL="${HALDIR_TTL:-3600}"

# Convert comma-separated scopes to JSON array
SCOPES_JSON=$(echo "$SCOPES_CSV" | jq -R 'split(",")')

# Build request payload
PAYLOAD=$(jq -n \
    --arg agent_id "$AGENT_ID" \
    --argjson scopes "$SCOPES_JSON" \
    --argjson ttl "$TTL" \
    '{agent_id: $agent_id, scopes: $scopes, ttl: $ttl}')

# Add spend_limit if provided
if [ -n "$SPEND_LIMIT" ]; then
    PAYLOAD=$(echo "$PAYLOAD" | jq --argjson limit "$SPEND_LIMIT" '. + {spend_limit: $limit}')
fi

echo "::group::Haldir Session"
echo "[*] Creating governed session for agent: $AGENT_ID"
echo "[*] Scopes: $SCOPES_CSV"
echo "[*] TTL: ${TTL}s"
if [ -n "$SPEND_LIMIT" ]; then
    echo "[*] Spend limit: \$${SPEND_LIMIT}"
fi

# Create session via Haldir API
HTTP_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST "${BASE_URL}/v1/sessions" \
    -H "Authorization: Bearer ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")

HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed '$d')
HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tail -n 1)

if [ "$HTTP_STATUS" -ne 201 ]; then
    echo "::error::Haldir session creation failed (HTTP $HTTP_STATUS): $HTTP_BODY"
    exit 1
fi

# Extract outputs
SESSION_ID=$(echo "$HTTP_BODY" | jq -r '.session_id')
SESSION_SCOPES=$(echo "$HTTP_BODY" | jq -c '.scopes')
EXPIRES_AT=$(echo "$HTTP_BODY" | jq -r '.expires_at')
SESSION_SPEND_LIMIT=$(echo "$HTTP_BODY" | jq -r '.spend_limit // "none"')

echo "[+] Session created: $SESSION_ID"
echo "[+] Scopes: $SESSION_SCOPES"
echo "[+] Expires: $EXPIRES_AT"
echo "[+] Spend limit: $SESSION_SPEND_LIMIT"
echo "::endgroup::"

# Set GitHub Action outputs
echo "session_id=$SESSION_ID" >> "$GITHUB_OUTPUT"
echo "scopes=$SESSION_SCOPES" >> "$GITHUB_OUTPUT"
echo "expires_at=$EXPIRES_AT" >> "$GITHUB_OUTPUT"

# Mask the session ID in logs (it's a bearer token for the session)
echo "::add-mask::$SESSION_ID"
