#!/usr/bin/env bash
# Plays the human in `spotagentiq demo`: approves the held email, rejects the
# held delete, then exits. Used by CI and by the demo recording (demo.tape).
#
#   scripts/auto-approve.sh &
#   spotagentiq demo
#
# Needs curl and jq.
set -euo pipefail

URL=${SPOTAGENTIQ_URL:-http://localhost:8484}
TOKEN=${SPOTAGENTIQ_TOKEN:-demo-token}
DELAY=${DELAY:-3}          # seconds a call stays visibly held before the decision
APPROVER=${APPROVER:-jordan (via Slack)}

decided=0
deadline=$((SECONDS + 120))
while [ "$decided" -lt 2 ] && [ "$SECONDS" -lt "$deadline" ]; do
  req=$(curl -fsS -H "Authorization: Bearer $TOKEN" "$URL/api/state" 2>/dev/null |
    jq -r '.pending[0] // empty | "\(.id) \(.tool)"' 2>/dev/null || true)
  if [ -z "$req" ]; then
    sleep 0.5
    continue
  fi
  id=${req%% *}
  tool=${req#* }
  decision=reject
  [ "$tool" = "send_email" ] && decision=approve

  sleep "$DELAY"
  curl -fsS -o /dev/null -X POST "$URL/api/decide" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "$(jq -n --arg id "$id" --arg d "$decision" --arg a "$APPROVER" \
      '{id: $id, decision: $d, approver: $a}')"
  decided=$((decided + 1))
done

[ "$decided" -eq 2 ]
