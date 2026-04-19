#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATTACKER_MAC="${1:-00:00:00:00:00:04}"
LOG_FILE="$PROJECT_ROOT/logs/block_events.log"

echo "Checking OpenFlow block rule for attacker MAC: $ATTACKER_MAC"
FLOW_MATCH=$(sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -i "priority=200" | grep -i "$ATTACKER_MAC" || true)

if [[ -n "$FLOW_MATCH" ]]; then
  echo "[PASS] Blocking flow exists on switch s1"
  echo "$FLOW_MATCH"
else
  echo "[FAIL] No blocking flow found on switch s1 for $ATTACKER_MAC"
fi

echo
if [[ -f "$LOG_FILE" ]]; then
  echo "Recent blocking events from $LOG_FILE"
  tail -n 40 "$LOG_FILE" | grep -E "host_blocked|block_verified|host_unblocked" || true
else
  echo "Log file not found yet: $LOG_FILE"
fi
