#!/usr/bin/env bash
#
# scripts/uat/scenarios/attack-runbook/attack.sh
#
# Wraps scripts/qa/attack-runbook.sh as the L5 attack phase. SCPs the runbook
# to the target VM, executes it once, surfaces the exit code. The system-test
# driver then polls the server REST API for each rule_id in expected.yaml.
#
# This is intentionally a THIN wrapper: scripts/qa/attack-runbook.sh keeps
# its full interactive-demo shape (per-step pacing, ascii separators, human-
# readable EXPECTED_ALERTS summary) so a developer can still ssh into the VM
# and run it directly. M9 just adds an asserted automation layer around it.
#
# Invoked by scripts/uat/system-test.sh with:
#   UAT_VM_SSH_TARGET   ssh target (e.g. victor@192.168.64.7)
#   UAT_HOST_ID         the VM's host_id on the server
#   UAT_SCRIPT_DIR      scripts/uat/ absolute path

# `set -e` so a failing SCP / SSH aborts the wrapper immediately and the
# system-test driver picks up the non-zero exit code (mapped to scenario
# FAIL). Without -e the script would log "runbook complete" and exit 0
# even after a failed remote command, producing a false PASS.
set -eEuo pipefail

: "${UAT_VM_SSH_TARGET:?driver did not set UAT_VM_SSH_TARGET}"
: "${UAT_SCRIPT_DIR:?driver did not set UAT_SCRIPT_DIR}"

# shellcheck disable=SC1091  # sourced path computed from UAT_SCRIPT_DIR; shellcheck cannot follow
. "$UAT_SCRIPT_DIR/lib/common.sh"

REPO_ROOT="$(cd "$UAT_SCRIPT_DIR/../.." && pwd)"
RUNBOOK="$REPO_ROOT/scripts/qa/attack-runbook.sh"

if [[ ! -f "$RUNBOOK" ]]; then
  uat_log attack-runbook "missing $RUNBOOK"
  exit 1
fi

uat_log attack-runbook "copying runbook to VM"
uat_scp "$RUNBOOK" "$UAT_VM_SSH_TARGET:/tmp/attack-runbook.sh"

uat_log attack-runbook "executing runbook on VM"
# EDR_RUNBOOK_PACE_SECONDS=0 so the runbook fires the seven attacks back to
# back. The system-test driver's polling window (120s per rule per
# expected.yaml) absorbs the ingest + detection latency afterwards.
# Prepend /usr/local/bin so the runbook's `command -v go` (privilege_launchd_plist_write step) finds a Go toolchain
# installed there; a non-login SSH shell otherwise sees only /usr/bin:/bin:/usr/sbin:/sbin. $PATH is single-quoted so
# it expands on the VM, not locally.
uat_ssh "$UAT_VM_SSH_TARGET" 'PATH=/usr/local/bin:$PATH EDR_RUNBOOK_PACE_SECONDS=0 bash /tmp/attack-runbook.sh'

uat_log attack-runbook "runbook complete"
