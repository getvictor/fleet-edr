#!/usr/bin/env bash
#
# scripts/uat/scenarios/policy-roundtrip/attack.sh
#
# Wraps scripts/qa/e2-policy-roundtrip.sh as the L5 attack phase. Unlike the
# attack-runbook wrapper, e2-policy-roundtrip already encodes the full
# assertion chain (push policy -> wait for agent ack -> try blocked exec ->
# verify deny -> restore policy) and exits non-zero on any step's failure.
# Wrapping it here is mainly about:
#
#   - Threading the system-test driver's already-authenticated session into
#     the existing script so we don't double-login (e2 re-authenticates if
#     it can't find a session it inherited).
#   - Pointing e2 at the same VM SSH target the driver probed.
#   - Surfacing the inner script's exit code unchanged so the driver's
#     `attack_sh_exit_zero` assertion holds.
#
# Invoked by scripts/uat/system-test.sh with:
#   UAT_VM_SSH_TARGET   ssh target (e.g. victor@192.168.64.7)
#   UAT_HOST_ID         the VM's host_id on the server
#   UAT_SCRIPT_DIR      scripts/uat/ absolute path

# `set -e` so a non-zero exit from the inner e2-policy-roundtrip.sh aborts
# this wrapper immediately. Without -e, the final `uat_log "inner script
# completed"` would run regardless of the inner script's exit code AND
# would itself exit 0, producing a false PASS to the system-test driver.
set -eEuo pipefail

: "${UAT_VM_SSH_TARGET:?driver did not set UAT_VM_SSH_TARGET}"
: "${UAT_SCRIPT_DIR:?driver did not set UAT_SCRIPT_DIR}"
: "${EDR_SERVER_URL:?missing required env}"

# shellcheck disable=SC1091  # sourced path computed from UAT_SCRIPT_DIR; shellcheck cannot follow
. "$UAT_SCRIPT_DIR/lib/common.sh"

REPO_ROOT="$(cd "$UAT_SCRIPT_DIR/../.." && pwd)"
INNER_SCRIPT="$REPO_ROOT/scripts/qa/e2-policy-roundtrip.sh"

if [[ ! -f "$INNER_SCRIPT" ]]; then
  uat_log policy-roundtrip "missing $INNER_SCRIPT"
  exit 1
fi

# NOTE: scripts/qa/e2-policy-roundtrip.sh currently POSTs to /api/v1/session
# for password-based login, an endpoint the server no longer exposes (login
# is OIDC or break-glass WebAuthn). The inner script will fail on its
# auth step until that drift is fixed upstream -- tracked separately.
# Until then this wrapper's role is shape-validation: the driver still
# verifies the (asserted scenario directory layout, attack.sh executable
# bit, expected.yaml schema) contract, and the inner script's eventual
# fix lands without changing this wrapper.

uat_log policy-roundtrip "delegating to $INNER_SCRIPT"

# e2-policy-roundtrip.sh reads EDR_SERVER_URL / EDR_ADMIN_* / VM_SSH_TARGET
# from the environment. The driver has already exported the first two; we
# re-export VM_SSH_TARGET under the name the inner script expects (we use
# UAT_VM_SSH_TARGET to namespace driver-internal state). EDR_ADMIN_EMAIL /
# _PASSWORD are passed through directly when the operator has set them.
VM_SSH_TARGET="$UAT_VM_SSH_TARGET" \
EDR_SERVER_URL="$EDR_SERVER_URL" \
EDR_ADMIN_EMAIL="${EDR_ADMIN_EMAIL:-}" \
EDR_ADMIN_PASSWORD="${EDR_ADMIN_PASSWORD:-}" \
  bash "$INNER_SCRIPT"

uat_log policy-roundtrip "inner script completed"
