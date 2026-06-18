#!/usr/bin/env bash
#
# scripts/uat/system-test.sh: UAT plan M9 driver (L5 layer).
#
# Runs one scenario from scripts/uat/scenarios/<name>/ against the edr-qa VM,
# polls the server's REST API for the expected detections, and asserts pass /
# fail per the scenario's expected.yaml. This is the asserted automation
# layer; scripts/qa/*.sh remain the interactive demos.
#
# Usage:
#   scripts/uat/system-test.sh <scenario-name> [options]
#
# Options:
#   --skip-install        Skip PKG install + extension-activation wait. Useful
#                         when iterating on a scenario against an already-
#                         enrolled VM.
#   --pkg-path=PATH       Override the PKG path; default is dist/fleet-edr-*.pkg
#                         (the release pipeline output, see packaging/pkg/).
#   --dry-run             Don't actually SSH / curl anything. Walks the
#                         scenario shape so a contributor can verify the
#                         orchestration before driving real infrastructure.
#
# Required environment:
#   EDR_SERVER_URL          e.g. https://edr.local:8088 (no trailing slash)
#   EDR_SESSION_COOKIE      Pre-minted `edr_session` cookie value. The server
#                           has no password-based POST /api/session login;
#                           operator does ONE browser break-glass / OIDC login,
#                           copies the cookie from devtools, and exports it
#                           here. Reused across many scenario runs until the
#                           session expires.
#   VM_SSH_TARGET           defaults to victor@192.168.64.7 (edr-qa)
#                           NOT edr-dev (192.168.64.5); L5 contract is
#                           SIP-on + Gatekeeper-on, which only edr-qa
#                           provides. Running against edr-dev contaminates
#                           the snapshot for release validation.
#   EDR_ADMIN_EMAIL         Optional; passed through to scripts/qa/* wrappers
#                           that still display it in their summary output.
#                           Not used by this driver itself.
#
# Exit codes:
#   0  All scenario assertions passed.
#   1  Driver error (bad args, missing env, scenario not found, etc).
#   2  Scenario ran but at least one assertion failed (the scenario's
#      attack.sh exited non-zero OR an expected alert did not appear within
#      its SLA).

set -eEuo pipefail

# Locate the driver's own directory so relative paths resolve from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091  # sourced path is computed at runtime from $SCRIPT_DIR; shellcheck cannot follow it statically
. "$SCRIPT_DIR/lib/common.sh"

UAT_TMPDIR="$(mktemp -d)"
export UAT_TMPDIR
# Capture $? at trap entry and re-exit with it so the EXIT trap's cleanup
# does not overwrite a failure status. Without `exit $rc`, the trap's `rm`
# succeeds (status 0) and the shell exits 0 even when the script body
# triggered a non-zero exit.
# SC2154: `rc` is assigned inside the single-quoted trap body; shellcheck
# can't statically see the assignment but it's correct at runtime.
# shellcheck disable=SC2154
trap 'rc=$?; rm -rf "$UAT_TMPDIR"; exit $rc' EXIT

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

usage() {
  sed -n '3,42p' "$0" | sed 's/^# //;s/^#//'
  exit "${1:-1}"
}

SCENARIO=""
UAT_SKIP_INSTALL=0
UAT_PKG_PATH=""
UAT_DRY_RUN=0
export UAT_DRY_RUN

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-install) UAT_SKIP_INSTALL=1; shift ;;
    --pkg-path=*)   UAT_PKG_PATH="${1#--pkg-path=}"; shift ;;
    --dry-run)      UAT_DRY_RUN=1; export UAT_DRY_RUN; shift ;;
    -h|--help)      usage 0 ;;
    --*)            uat_log driver "unknown option: $1"; usage 1 ;;
    *)
      if [[ -n "$SCENARIO" ]]; then
        uat_log driver "unexpected extra argument: $1"
        usage 1
      fi
      SCENARIO="$1"
      shift
      ;;
  esac
done

if [[ -z "$SCENARIO" ]]; then
  uat_log driver "missing required <scenario-name>"
  usage 1
fi

SCENARIO_DIR="$SCRIPT_DIR/scenarios/$SCENARIO"
if [[ ! -d "$SCENARIO_DIR" ]]; then
  uat_log driver "no such scenario: $SCENARIO_DIR"
  exit 1
fi
if [[ ! -x "$SCENARIO_DIR/attack.sh" ]]; then
  uat_log driver "missing or non-executable attack.sh in $SCENARIO_DIR"
  exit 1
fi
if [[ ! -f "$SCENARIO_DIR/expected.yaml" ]]; then
  uat_log driver "missing expected.yaml in $SCENARIO_DIR"
  exit 1
fi

# ---------------------------------------------------------------------------
# Environment validation
# ---------------------------------------------------------------------------

VM_SSH_TARGET="${VM_SSH_TARGET:-victor@192.168.64.7}"

# Soft-required: dry-run only needs the scenario to load. Explicit `[[ -z ]]`
# checks + `exit 1` (rather than `${VAR:?msg}`) so the failure mode propagates
# cleanly through the EXIT trap's $? capture: bash's `:?` substitution exits
# the shell but resets $? to 0 at trap entry, masking the failure.
if [[ "$UAT_DRY_RUN" != "1" ]]; then
  if [[ -z "${EDR_SERVER_URL:-}" ]]; then
    uat_log driver "missing required env EDR_SERVER_URL -- see usage"
    exit 1
  fi
  if [[ -z "${EDR_SESSION_COOKIE:-}" ]]; then
    uat_log driver "missing required env EDR_SESSION_COOKIE -- see scripts/uat/README.md \"Auth flow\""
    exit 1
  fi
fi

uat_log driver "scenario=$SCENARIO vm=$VM_SSH_TARGET dry_run=$UAT_DRY_RUN"

# Record the wall-clock baseline up front so the alert poll later filters out
# any pre-existing alerts on the same (host_id, rule_id) tuple from prior
# scenario runs against this host.
SCENARIO_STARTED_UNIX=$(date +%s)

# ---------------------------------------------------------------------------
# Step 1: SSH probe
# ---------------------------------------------------------------------------

if [[ "$UAT_DRY_RUN" != "1" ]]; then
  if ! uat_ssh "$VM_SSH_TARGET" "echo ssh-probe-ok" >/dev/null; then
    uat_log driver "ssh probe to $VM_SSH_TARGET failed; check BatchMode keyed access"
    exit 1
  fi
  uat_log driver "ssh probe ok"
fi

# ---------------------------------------------------------------------------
# Step 2: PKG install + extension activation (optional)
# ---------------------------------------------------------------------------

if [[ "$UAT_SKIP_INSTALL" != "1" ]]; then
  if [[ -z "$UAT_PKG_PATH" ]]; then
    # Pick the most recent fleet-edr-*.pkg in dist/. The release pipeline
    # writes there; for ad-hoc runs the operator passes --pkg-path explicitly.
    # shellcheck disable=SC2012  # ls -t is fine: release PKG filenames are alphanumeric semver, no spaces
    UAT_PKG_PATH=$(ls -t dist/fleet-edr-*.pkg 2>/dev/null | head -1 || true)
  fi
  if [[ -z "$UAT_PKG_PATH" || ! -f "$UAT_PKG_PATH" ]]; then
    if [[ "$UAT_DRY_RUN" == "1" ]]; then
      UAT_PKG_PATH="dist/fleet-edr-DRYRUN.pkg"
    else
      uat_log driver "no PKG found; build one via packaging/pkg/build.sh or pass --pkg-path or --skip-install"
      exit 1
    fi
  fi
  uat_log driver "installing PKG: $UAT_PKG_PATH"
  uat_scp "$UAT_PKG_PATH" "$VM_SSH_TARGET:/tmp/edr-uat.pkg"
  uat_ssh "$VM_SSH_TARGET" "sudo installer -pkg /tmp/edr-uat.pkg -target /"

  # 60s extension-activation budget per extension-testing.md L5 spec. Catches
  # signing / notarization regressions: an unsigned PKG installs but the
  # system extension never activates.
  uat_log driver "waiting up to 60s for extension activation"
  if ! uat_wait_for_extension "$VM_SSH_TARGET" 60; then
    uat_log driver "extension did not activate within 60s; check sudo systemextensionsctl list on the VM"
    exit 2
  fi
  uat_log driver "extension activated"
fi

# ---------------------------------------------------------------------------
# Step 3: Server session warmup + host enrolment poll
# ---------------------------------------------------------------------------

if ! uat_server_warmup; then
  uat_log driver "server session warmup failed (see error above)"
  exit 1
fi

# Read scenario metadata. We use a minimal-dependency yq alternative: each
# expected.yaml has its `scenario_id`, `within_seconds`, and (optional)
# `rules:` block parseable via plain awk; the schema is documented in
# scripts/uat/README.md and each scenario's README.
#
# Inline-comment handling: `sub(/[[:space:]]*#.*$/, "", $2)` strips any
# trailing `# comment` from the value before quote / whitespace cleanup, so
# a contributor who annotates a field doesn't silently corrupt the parsed
# value.
SCENARIO_ID=$(awk -F: '
  /^scenario_id:/ {
    sub(/[[:space:]]*#.*$/, "", $2)
    gsub(/[ \"\x27]/, "", $2)
    print $2
    exit
  }
' "$SCENARIO_DIR/expected.yaml")
SCENARIO_WINDOW=$(awk -F: '
  /^within_seconds:/ {
    sub(/[[:space:]]*#.*$/, "", $2)
    gsub(/[ ]/, "", $2)
    print $2
    exit
  }
' "$SCENARIO_DIR/expected.yaml")
SCENARIO_WINDOW="${SCENARIO_WINDOW:-120}"
if [[ -z "$SCENARIO_ID" ]]; then
  uat_log driver "expected.yaml is missing scenario_id"
  exit 1
fi
uat_log driver "loaded scenario_id=$SCENARIO_ID within_seconds=$SCENARIO_WINDOW"

# The agent enrols under the Mac's hardware UUID (IOPlatformUUID), and
# /api/hosts (api.HostSummary) is keyed by that host_id with NO hostname field,
# so we resolve the UUID on the VM and match the enrolment poll on host_id.
VM_HOST_ID="${UAT_VM_HOST_ID:-$(uat_ssh "$VM_SSH_TARGET" "ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformUUID/{print \$NF}' | tr -dc '[:alnum:]-'" || echo "")}"
if [[ -z "$VM_HOST_ID" ]]; then
  if [[ "$UAT_DRY_RUN" == "1" ]]; then
    VM_HOST_ID="00000000-0000-0000-0000-DRYRUNDRYRUN"
  else
    uat_log driver "could not resolve VM hardware UUID via ioreg; set UAT_VM_HOST_ID explicitly"
    exit 1
  fi
fi
uat_log driver "polling for enrolment of host host_id=$VM_HOST_ID"
HOST_ID=$(uat_wait_for_host_enrolment "$VM_HOST_ID" 30 || true)
if [[ -z "$HOST_ID" ]]; then
  uat_log driver "host $VM_HOST_ID did not enrol within 30s"
  exit 2
fi
uat_log driver "host enrolled host_id=$HOST_ID"

# ---------------------------------------------------------------------------
# Step 4: Run the scenario's attack.sh
# ---------------------------------------------------------------------------

uat_log driver "running scenario attack.sh"
ATTACK_EXIT=0
if [[ "$UAT_DRY_RUN" == "1" ]]; then
  uat_log driver "DRY-RUN attack.sh"
else
  # Disable errexit just for this invocation so a failed scenario reaches the
  # exit-code check below instead of aborting the driver. The driver maps a
  # non-zero attack.sh to exit 2 (scenario fail) below so the operator gets a
  # clean PASS / FAIL summary.
  set +e
  UAT_VM_SSH_TARGET="$VM_SSH_TARGET" \
  UAT_HOST_ID="$HOST_ID" \
  UAT_SCRIPT_DIR="$SCRIPT_DIR" \
    "$SCENARIO_DIR/attack.sh"
  ATTACK_EXIT=$?
  set -e
fi
if [[ "$ATTACK_EXIT" != "0" ]]; then
  uat_log driver "attack.sh exited $ATTACK_EXIT"
  exit 2
fi

# ---------------------------------------------------------------------------
# Step 5: Poll for expected alerts (if any)
# ---------------------------------------------------------------------------

# Pull the `rule_id` lines out of the rules: block. Plain awk avoids a yq
# dependency. The format is intentionally narrow: one `- rule_id:` per entry.
# Other fields (severity, expect, description) are operator-facing
# documentation only.
#
# `mapfile` is avoided so this works on macOS's bundled bash 3.2 (same
# constraint scripts/qa/README.md calls out). The while-read pattern with an
# initial-empty array is the bash-3-safe equivalent.
#
# Awk semantics:
#  - First pass: extract the rules: block (start on `rules:`, stop at the
#    next top-level YAML key). The naive `/^rules:/,/^[a-z]/` range form
#    self-terminates on the `rules:` line itself (it matches BOTH endpoints)
#    so we use an explicit in-block flag instead.
#  - Second pass: pick each `- rule_id:` value. The `sub` strips inline
#    `# comments`. The `gsub` cleans quotes, whitespace, and the leading
#    `-` from the list-item marker; it does NOT strip embedded hyphens
#    (the char class only covers the very-first dash and is anchored at
#    the start of the value via `sub`'s prior strip-leading-space-then-dash
#    pass) so rule_ids like `suspicious-curl-pipe-sh` survive intact.
SCENARIO_RULES=()
while IFS= read -r rid; do
  [[ -n "$rid" ]] && SCENARIO_RULES+=("$rid")
done < <(
  awk '/^rules:/ {in_rules=1; next} /^[a-z][a-zA-Z_]*:/ {in_rules=0} in_rules' \
      "$SCENARIO_DIR/expected.yaml" \
    | awk -F: '
        /^[[:space:]]*-[[:space:]]*rule_id:/ {
          sub(/[[:space:]]*#.*$/, "", $2)
          gsub(/[ \"\x27]/, "", $2)
          print $2
        }
      '
)

if [[ ${#SCENARIO_RULES[@]} -eq 0 ]]; then
  uat_log driver "no rules block in expected.yaml -- scenario passes on attack.sh exit 0 alone"
  uat_log driver "PASS scenario=$SCENARIO_ID"
  exit 0
fi

uat_log driver "polling for ${#SCENARIO_RULES[@]} expected alerts within ${SCENARIO_WINDOW}s"
PASSED=0
FAILED=0
for rule_id in "${SCENARIO_RULES[@]}"; do
  if uat_poll_alerts "$HOST_ID" "$rule_id" "$SCENARIO_WINDOW" "$SCENARIO_STARTED_UNIX"; then
    uat_log driver "  hit: $rule_id"
    PASSED=$(( PASSED + 1 ))
  else
    uat_log driver "  miss: $rule_id (no alert within ${SCENARIO_WINDOW}s since scenario start)"
    FAILED=$(( FAILED + 1 ))
  fi
done

uat_log driver "scenario=$SCENARIO_ID rules_passed=$PASSED rules_failed=$FAILED"
if [[ "$FAILED" -gt 0 ]]; then
  uat_log driver "FAIL scenario=$SCENARIO_ID"
  exit 2
fi

uat_log driver "PASS scenario=$SCENARIO_ID"
exit 0
