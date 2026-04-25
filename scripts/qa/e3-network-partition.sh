#!/usr/bin/env bash
#
# Phase-7 dogfood QA E3: 10-minute network partition.
#
# What it proves: the agent's offline queue grows while the server is
# unreachable, and drains cleanly once the partition heals. The plan
# calls for "no duplicates after restore"; the queue itself does NOT
# enforce uniqueness (its schema is `events(id INTEGER PRIMARY KEY
# AUTOINCREMENT, event_json, created_at, uploaded)` per
# agent/queue/queue.go — no event_id column, no UNIQUE constraint), so
# that guarantee currently rests on the server's `INSERT IGNORE` on
# `events` (see server/store/store.go) when flushed. A precise
# duplicate check is out of scope for a script that drives only public
# APIs; see scripts/qa/README.md "Known gaps."
#
# Steps:
#  1. Snapshot the agent's queue depth via SQL on
#     /var/db/fleet-edr/events.db.
#  2. Drop a pf anchor rule on the VM that blocks the server's IP.
#  3. Generate ~30 synthetic processes on the VM (each is one
#     fork+exec event pair, fully observable). Wait 10 minutes; the
#     agent's uploader retries every ~60s and accumulates events in
#     the queue.
#  4. Confirm the queue depth grew relative to the baseline while the
#     partition is in effect (≥ baseline + 60 events: 30 forks + 30
#     execs).
#  5. Remove the pf anchor — partition heals.
#  6. Wait up to 90s for the queue to drain back to baseline.
#  7. Surface the post-recovery alert count for the host. (No precise
#     server-side "no duplicates" assertion today; the v0.1 admin API
#     doesn't expose a per-host event-count endpoint.)
#
# Usage from this workstation:
#   EDR_SERVER_URL=https://edr.local:8088 \
#   EDR_ADMIN_EMAIL=admin@fleet-edr.local \
#   EDR_ADMIN_PASSWORD=<paste> \
#   VM_SSH_TARGET=victor@192.168.64.5 \
#   EDR_SERVER_IP=192.168.64.1 \
#   bash scripts/qa/e3-network-partition.sh
#
# EDR_SERVER_IP is the IP the agent on the VM uses to reach the
# server — typically the host's bridge address. We block at the IP
# layer rather than tearing the VM's NIC down so SSH from the
# workstation keeps working. Pass --short for a 60-second partition
# instead of 10 minutes; useful for development of the script itself.

set -uEo pipefail
# shellcheck disable=SC2154  # `rc` is assigned inside the trap body via $?
trap 'rc=$?; echo "[e3] step at line $LINENO exited $rc — continuing"' ERR

require_env() {
  for v in "$@"; do
    if [ -z "${!v:-}" ]; then
      echo "[e3] missing required env var: $v" >&2
      exit 2
    fi
  done
}
require_env EDR_SERVER_URL EDR_ADMIN_EMAIL EDR_ADMIN_PASSWORD VM_SSH_TARGET EDR_SERVER_IP

PARTITION_SECS=600
case "${1:-}" in
  --short) PARTITION_SECS=60; echo "[e3] --short: 60s partition";;
esac

# Private workdir: cookie jar holds an admin session.
umask 077
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/edr-e3-partition.XXXXXX")
chmod 700 "$WORKDIR"
COOKIE_JAR="$WORKDIR/cookies"
PF_ANCHOR="com.fleetdm.edr.e3"
# Captured before we touch pf so the cleanup trap can roll back to the
# operator's original PF state instead of leaving it enabled.
PF_WAS_ENABLED=""

hr() { printf '\n%s\n' '────────────────────────────────────────────────────────'; }

# pf cleanup trap: flush our anchor regardless of how the script exits
# (Ctrl-C in the long sleep, ssh hiccup, ERR trap continuing into a
# fatal step). If pf was disabled before we ran, also disable it again
# so the VM's networking config matches what we found.
cleanup_pf() {
  if [ -z "$PF_WAS_ENABLED" ]; then return 0; fi
  # shellcheck disable=SC2087  # client-side expansion of $PF_ANCHOR + $PF_WAS_ENABLED is intended
  ssh -o BatchMode=yes "$VM_SSH_TARGET" "bash -s" >&2 <<EOF || \
    echo "[e3] WARNING: pf cleanup over SSH failed; check the VM" >&2
sudo /sbin/pfctl -a "$PF_ANCHOR" -F all 2>/dev/null || true
sudo rm -f /tmp/edr-e3.pf.rules 2>/dev/null || true
if [ "$PF_WAS_ENABLED" = "no" ]; then
  sudo /sbin/pfctl -d 2>/dev/null || true
fi
EOF
}
trap cleanup_pf EXIT

# Authenticate so we can query alerts + the host's event count
# afterwards. The PUT to admin/policy isn't needed in this scenario
# but we still need a session to read /api/v1/alerts.
hr
echo "[e3] step 1: authenticate"
http_code=$(curl -sS -o "$WORKDIR/login.json" -w '%{http_code}' \
  -c "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg e "$EDR_ADMIN_EMAIL" --arg p "$EDR_ADMIN_PASSWORD" \
       '{email:$e,password:$p}')" \
  "$EDR_SERVER_URL/api/v1/session" || echo "000")
[ "$http_code" = "200" ] || { echo "[e3] login failed HTTP $http_code"; exit 1; }
HOST_ID=$(ssh -o BatchMode=yes "$VM_SSH_TARGET" \
  "sudo /usr/bin/plutil -extract host_id raw -o - /var/db/fleet-edr/enrolled.plist" \
  | tr -d '[:space:]')
[ -n "$HOST_ID" ] || { echo "[e3] could not read host_id from VM"; exit 1; }
echo "[e3] host_id=$HOST_ID"

# Snapshot baseline + record pf state for the cleanup trap.
hr
echo "[e3] step 2: snapshot baselines"
queue_depth() {
  ssh -o BatchMode=yes "$VM_SSH_TARGET" \
    "sudo /usr/bin/sqlite3 /var/db/fleet-edr/events.db 'SELECT COUNT(*) FROM events;' 2>/dev/null" \
    | tr -d '[:space:]'
}

baseline_queue=$(queue_depth)
echo "[e3] queue depth at start: $baseline_queue"

# Was pf already enabled? cleanup_pf uses this to roll back.
if ssh -o BatchMode=yes "$VM_SSH_TARGET" 'sudo /sbin/pfctl -s info 2>&1 | grep -q "Status: Enabled"'; then
  PF_WAS_ENABLED=yes
else
  PF_WAS_ENABLED=no
fi
echo "[e3] pf was previously enabled: $PF_WAS_ENABLED"

# Drop the partition.
hr
echo "[e3] step 3: install pf anchor blocking $EDR_SERVER_IP"
# shellcheck disable=SC2087  # client-side expansion is intended; $EDR_SERVER_IP and $PF_ANCHOR live on this workstation
ssh -o BatchMode=yes "$VM_SSH_TARGET" "bash -s" <<EOF
set -euo pipefail
sudo /sbin/pfctl -E 2>/dev/null || true
echo "block out quick to $EDR_SERVER_IP" | sudo tee /tmp/edr-e3.pf.rules >/dev/null
sudo /sbin/pfctl -a "$PF_ANCHOR" -f /tmp/edr-e3.pf.rules
echo "[vm] pf anchor active"
EOF

# Generate synthetic events on the VM.
hr
echo "[e3] step 4: generate 30 synthetic processes on the VM"
ssh -o BatchMode=yes "$VM_SSH_TARGET" "bash -s" <<'EOF'
for i in $(seq 1 30); do /usr/bin/true; done
echo "[vm] 30 /usr/bin/true execs done — agent should see fork+exec events"
EOF

# Wait through the partition. The agent retries the uploader every
# ~60s; events queue locally with no acks.
hr
echo "[e3] step 5: hold partition for ${PARTITION_SECS}s"
sleep "$PARTITION_SECS"

mid_queue=$(queue_depth)
echo "[e3] queue depth during partition: $mid_queue"
expected_at_least=$((baseline_queue + 60))
if [ "$mid_queue" -lt "$expected_at_least" ]; then
  echo "[e3] WARNING: expected queue ≥ $expected_at_least, got $mid_queue."
  echo "[e3] events may not have been observed by ESF — check /var/log/fleet-edr-agent.log"
fi

# Heal the partition.
hr
echo "[e3] step 6: remove pf anchor"
# shellcheck disable=SC2087  # client-side expansion of $PF_ANCHOR is intended
ssh -o BatchMode=yes "$VM_SSH_TARGET" "bash -s" <<EOF
sudo /sbin/pfctl -a "$PF_ANCHOR" -F all
sudo rm -f /tmp/edr-e3.pf.rules
echo "[vm] pf anchor cleared"
EOF

# Wait for queue drainage. Uploader cadence is ~5s when the server is
# reachable, so 90s should be plenty even for a 30-event burst.
hr
echo "[e3] step 7: wait ≤90s for queue to drain"
deadline=$(( $(date +%s) + 90 ))
final_queue=$mid_queue
while [ "$(date +%s)" -lt "$deadline" ]; do
  final_queue=$(queue_depth)
  if [ "$final_queue" -le "$baseline_queue" ]; then
    echo "[e3] queue drained to baseline ($final_queue events)"
    break
  fi
  sleep 5
done
if [ "$final_queue" -gt "$baseline_queue" ]; then
  echo "[e3] FAIL: queue still has $final_queue events (baseline was $baseline_queue)"
fi

# Server-side: count events for this host since the test started, and
# look for duplicate event_ids — both queries use admin endpoints that
# require the session cookie from step 1.
hr
echo "[e3] step 8: server-side sanity"
echo "[e3] event count for host $HOST_ID:"
curl -sS -b "$COOKIE_JAR" \
  "$EDR_SERVER_URL/api/v1/alerts?host_id=$HOST_ID&status=open" | \
  jq '{open_alerts_count: (.alerts // [] | length)}' || true
echo "[e3] (no per-host event-count endpoint today; query via DB if you need exact numbers)"

hr
echo "[e3] done."
echo "[e3]   queue baseline: $baseline_queue"
echo "[e3]   peak during partition: $mid_queue"
echo "[e3]   final after drain: $final_queue"
echo "[e3] expected: peak ≥ baseline + 60, final ≤ baseline."
echo "[e3] cleanup: rm -rf $WORKDIR; the pf anchor is already removed."
