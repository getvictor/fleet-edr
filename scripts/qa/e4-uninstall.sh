#!/usr/bin/env bash
#
# Phase-7 dogfood QA E4: uninstaller round-trip.
#
# What it proves: the bundled `uninstall.sh` tears down everything
# the .pkg installed and the runtime state under /var/db, deactivates
# the system extension, but DELIBERATELY leaves /etc/fleet-edr.conf
# in place so a re-install picks up the same enrollment config
# without re-typing the secret. Plus, the host flips to "offline" in
# the admin UI within ~5 minutes of last_seen.
#
# Steps:
#  1. Confirm pre-state on the VM: agent running, sysext activated
#     enabled, the install receipts present.
#  2. Run /Library/Application Support/com.fleetdm.edr/uninstall.sh.
#  3. Assert post-state: LaunchDaemon unloaded, sysext gone, binaries
#     removed, /var/db/fleet-edr/ removed, /etc/fleet-edr.conf
#     PRESERVED.
#  4. Wait up to 6 minutes for the server's "offline" gauge to update
#     (default last_seen threshold is 5 min).
#  5. Optionally: re-run `installer -pkg` and verify the agent picks
#     up the preserved config without prompting for a new
#     enroll_secret. Off by default — pass --reinstall to opt in.
#
# Usage from this workstation:
#   EDR_SERVER_URL=https://edr.local:8088 \
#   EDR_ADMIN_EMAIL=admin@fleet-edr.local \
#   EDR_ADMIN_PASSWORD=<paste> \
#   VM_SSH_TARGET=victor@192.168.64.5 \
#   bash scripts/qa/e4-uninstall.sh
#
# Add --reinstall PATH/TO/fleet-edr-vX.Y.Z.pkg to also exercise the
# re-install half. The pkg path is the local file on this workstation
# we'll scp to the VM.

set -uEo pipefail
# shellcheck disable=SC2154  # `rc` is assigned inside the trap body via $?
trap 'rc=$?; echo "[e4] step at line $LINENO exited $rc — continuing"' ERR

require_env() {
  for v in "$@"; do
    if [[ -z "${!v:-}" ]]; then
      echo "[e4] missing required env var: $v" >&2
      exit 2
    fi
  done
  return 0
}
require_env EDR_SERVER_URL EDR_ADMIN_EMAIL EDR_ADMIN_PASSWORD VM_SSH_TARGET

# Constant for the SSH stdin-driver argument used on every remote-bash
# block below — Sonar S1192 flags `'bash -s'` four times; one constant
# satisfies it without changing behaviour.
BASH_S='bash -s'

REINSTALL_PKG=""
case "${1:-}" in
  --reinstall) shift; REINSTALL_PKG="${1:-}"; shift || true
    # Distinguish missing-arg from missing-file: a wrapper that drops args
    # would otherwise produce the confusing `pkg not found:` (no path) line.
    [[ -n "$REINSTALL_PKG" ]] || { echo "[e4] --reinstall requires a path to the .pkg" >&2; exit 2; }
    [[ -f "$REINSTALL_PKG" ]] || { echo "[e4] --reinstall pkg not found: $REINSTALL_PKG" >&2; exit 2; };;
  *) ;;
esac

# Private workdir: cookie jar + login response carry an admin session.
umask 077
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/edr-e4-uninstall.XXXXXX")
chmod 700 "$WORKDIR"
COOKIE_JAR="$WORKDIR/cookies"

hr() {
  printf '\n%s\n' '────────────────────────────────────────────────────────'
  return 0
}

# Pre-state. Each check prints "ok" or what was wrong; we don't bail
# on the first failure because the operator wants the whole picture.
hr
echo "[e4] step 1: verify pre-uninstall state on $VM_SSH_TARGET"
ssh -o BatchMode=yes "$VM_SSH_TARGET" "$BASH_S" <<'EOF'
set -uo pipefail
echo -n "[vm] LaunchDaemon present: "
test -f /Library/LaunchDaemons/com.fleetdm.edr.agent.plist && echo ok || echo MISSING
echo -n "[vm] LaunchDaemon running: "
sudo /bin/launchctl print system/com.fleetdm.edr.agent 2>/dev/null \
  | /usr/bin/grep -q 'state = running' && echo ok || echo NOT-RUNNING
echo -n "[vm] sysext activated enabled: "
/usr/bin/systemextensionsctl list 2>/dev/null \
  | /usr/bin/grep -q 'activated enabled.*com.fleetdm.edr' && echo ok || echo NOT-ACTIVATED
echo -n "[vm] agent binary present: "
test -x /usr/local/bin/fleet-edr-agent && echo ok || echo MISSING
echo -n "[vm] uninstaller present: "
test -x "/Library/Application Support/com.fleetdm.edr/uninstall.sh" && echo ok || echo MISSING
echo -n "[vm] /etc/fleet-edr.conf present: "
test -f /etc/fleet-edr.conf && echo ok || echo MISSING
echo -n "[vm] events.db present: "
test -f /var/db/fleet-edr/events.db && echo ok || echo MISSING
EOF

# Capture the host_id BEFORE the uninstall removes the enrolled
# plist, so we can later look up the host on the server side. Bail
# eagerly on empty: a downstream `select(.host_id==$id)` with $id=""
# matches nothing and would silently report "host offline" without
# ever talking to the server about a real host.
HOST_ID=$(ssh -o BatchMode=yes "$VM_SSH_TARGET" \
  "sudo /usr/bin/plutil -extract host_id raw -o - /var/db/fleet-edr/enrolled.plist 2>/dev/null" \
  | tr -d '[:space:]')
if [[ -z "$HOST_ID" ]]; then
  echo "[e4] could not read host_id from /var/db/fleet-edr/enrolled.plist" >&2
  echo "[e4] step 4's offline check would be meaningless without it; aborting." >&2
  exit 1
fi
echo "[e4] host_id=$HOST_ID"

# Run the uninstaller.
hr
echo "[e4] step 2: run uninstall.sh on the VM"
# shellcheck disable=SC2087
ssh -o BatchMode=yes "$VM_SSH_TARGET" "$BASH_S" <<EOF
set -uo pipefail
sudo "/Library/Application Support/com.fleetdm.edr/uninstall.sh" || \
  echo "[vm] uninstall.sh exited non-zero (some operations may be best-effort)"
EOF

# Post-state. Each line is a single assertion the operator can scan.
hr
echo "[e4] step 3: verify post-uninstall state"
ssh -o BatchMode=yes "$VM_SSH_TARGET" "$BASH_S" <<'EOF'
set -uo pipefail
echo -n "[vm] LaunchDaemon plist removed: "
test -f /Library/LaunchDaemons/com.fleetdm.edr.agent.plist && echo STILL-PRESENT || echo ok
echo -n "[vm] LaunchDaemon unloaded: "
sudo /bin/launchctl print system/com.fleetdm.edr.agent 2>/dev/null \
  | /usr/bin/grep -q 'state = running' && echo STILL-RUNNING || echo ok
echo -n "[vm] sysext deactivated: "
/usr/bin/systemextensionsctl list 2>/dev/null \
  | /usr/bin/grep -q 'activated.*com.fleetdm.edr' && echo STILL-ACTIVATED || echo ok
echo -n "[vm] agent binary removed: "
test -x /usr/local/bin/fleet-edr-agent && echo STILL-PRESENT || echo ok
echo -n "[vm] events.db removed: "
test -f /var/db/fleet-edr/events.db && echo STILL-PRESENT || echo ok
echo -n "[vm] /var/db/fleet-edr removed: "
test -d /var/db/fleet-edr && echo STILL-PRESENT || echo ok
echo -n "[vm] /etc/fleet-edr.conf preserved (intended): "
test -f /etc/fleet-edr.conf && echo ok || echo MISSING-DELETED
EOF

# Wait for the server's offline gauge. Default threshold is 5 min;
# we give 6 min plus a poll cadence to be confident.
hr
echo "[e4] step 4: wait ≤6 min for server to mark host offline"
http_code=$(curl -sS -o "$WORKDIR/login.json" -w '%{http_code}' \
  -c "$COOKIE_JAR" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg e "$EDR_ADMIN_EMAIL" --arg p "$EDR_ADMIN_PASSWORD" '{email:$e,password:$p}')" \
  "$EDR_SERVER_URL/api/v1/session" || echo "000")
if [[ "$http_code" != "200" ]]; then
  echo "[e4] login HTTP $http_code; offline check skipped"
else
  # /api/v1/hosts returns a top-level JSON array of HostSummary objects
  # per the OpenAPI spec — not an object with a `.hosts` field. Iterate
  # the array root.
  deadline=$(( $(date +%s) + 360 ))
  last_seen=""
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    last_seen=$(curl -sS -b "$COOKIE_JAR" \
      "$EDR_SERVER_URL/api/v1/hosts" 2>/dev/null \
      | jq -r --arg id "$HOST_ID" '.[]? | select(.host_id==$id) | .last_seen_ns // ""' \
      | tr -d '[:space:]')
    if [[ -z "$last_seen" ]]; then
      echo "[e4] host no longer in /api/v1/hosts list (or offline filter applied)"
      break
    fi
    age_s=$(( $(date +%s) - last_seen / 1000000000 ))
    if [[ "$age_s" -ge 300 ]]; then
      echo "[e4] host last_seen is $age_s s old → considered offline"
      break
    fi
    sleep 30
  done
fi

# Optional re-install half.
if [[ -n "$REINSTALL_PKG" ]]; then
  hr
  echo "[e4] step 5: re-install from $REINSTALL_PKG"
  scp -o BatchMode=yes "$REINSTALL_PKG" "$VM_SSH_TARGET:/tmp/"
  pkg_basename=$(basename "$REINSTALL_PKG")
  # shellcheck disable=SC2087  # client-side expansion of $pkg_basename is intended
  ssh -o BatchMode=yes "$VM_SSH_TARGET" "$BASH_S" <<EOF
set -uo pipefail
sudo /usr/sbin/installer -pkg "/tmp/$pkg_basename" -target /
EOF
  echo "[e4] re-installed; check that /etc/fleet-edr.conf was reused (no manual config step)"
  echo "[e4] verify the agent re-enrols with the SAME host_id ($HOST_ID) — the persisted token at"
  echo "[e4] /var/db/fleet-edr/enrolled.plist is recreated by the post-install only if the conf is read."
fi

hr
echo "[e4] done. Expected: every line in step 3 prints 'ok' except"
echo "[e4]   '/etc/fleet-edr.conf preserved (intended)' which also prints 'ok'."
echo "[e4] cleanup: rm -rf $WORKDIR"
