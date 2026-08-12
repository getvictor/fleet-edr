#!/usr/bin/env bash
#
# scripts/uat/scenarios/sensor-tamper/attack.sh
#
# L5 attack phase for the sensor_tamper rule (T1562.001, issue #684): switch
# off one of the EDR's own capture providers on a live VM and let the driver
# assert the alert.
#
# What this covers that the synthetic L6 corpus cannot. The corpus scenario
# injects a sensor_provider_transition event that already exists, so it proves
# the RULE reads it correctly and nothing else. Everything upstream of the
# rule is assumed: that stopping a real provider makes the extension notice,
# that it grades the stop a fault rather than a supported opt-out, that the
# agent diffs its liveness reports into a transition event, and that the event
# reaches the server at all. Those are four separate pieces of production code
# that the corpus never executes. This script exercises them on a real host.
#
# Contract with scripts/uat/system-test.sh:
#   UAT_VM_SSH_TARGET   ssh target (e.g. victor@192.168.64.5)
#   UAT_HOST_ID         the VM's host_id on the server
#   UAT_SCRIPT_DIR      scripts/uat/ absolute path
# The driver polls /api/alerts for the rule_ids in expected.yaml after this
# exits 0, so the alert assertion is the driver's job, not this script's.
#
# This script leaves the host HEALTHY. Disabling the mandatory content filter
# is repaired automatically by the agent's self-heal (issue #632) in about 35
# seconds, and the script waits for that repair and fails if it does not
# arrive: a scenario that left capture switched off would silently degrade
# every scenario that runs after it on the same VM.

set -eEuo pipefail

: "${UAT_VM_SSH_TARGET:?driver did not set UAT_VM_SSH_TARGET}"
: "${UAT_SCRIPT_DIR:?driver did not set UAT_SCRIPT_DIR}"

# shellcheck disable=SC1091  # sourced path computed from UAT_SCRIPT_DIR; shellcheck cannot follow
. "$UAT_SCRIPT_DIR/lib/common.sh"

# Rebuild the server-auth state in THIS process. The driver's warmup populates
# UAT_COOKIE_HEADER, but that is a bash array and arrays do not survive the
# environment, so a scenario that talks to the server has to warm up for
# itself from the plain EDR_SESSION_COOKIE var (app-control-block does the
# same). Without this, uat_server_get trips `set -u` on an unbound array.
uat_server_warmup

EDR_CLI="/Applications/Fleet EDR.app/Contents/MacOS/edr"

# The provider to switch off. The MANDATORY content filter, deliberately: the
# DNS proxy is opt-in, so #649 grades disabling it a supported configuration
# and reports it absent rather than stopped, which produces no event and no
# alert. Pointing this scenario at the DNS proxy would assert nothing and pass
# for the wrong reason.
PROVIDER="content_filter"

# How long to wait for the extension to report the provider stopped. The
# report rides the next liveness publish, which is prompt; this is a generous
# bound on "the extension noticed at all".
STOP_TIMEOUT=60

# How long to wait for the agent to put capture back. The self-heal's grace
# window is 30s and the enable itself takes a couple of seconds, so a real
# repair lands around 35s. A host that has not recovered by twice that has a
# broken self-heal, which is worth failing the scenario over: the rule under
# test exists precisely because the repair hides the tamper, and a repair that
# never happens means this VM is left without capture.
RECOVER_TIMEOUT=90

# host_is_healthy reports whether the SERVER currently considers this host to be
# capturing normally. Level state, read from the same surface an operator reads.
#
# This deliberately does NOT read the extension log to establish the starting
# state. The extension logs "Provider <name> is running" when a provider STARTS,
# not continuously, so a provider that has been up for an hour produces no line
# and a log-based precondition can never pass. That is not a hypothetical: the
# first version of this script did exactly that and failed every run at the
# precondition. Change-triggered signals answer "did it change"; they cannot
# answer "what is it now".
host_is_healthy() {
  local body="${UAT_TMPDIR:-/tmp}/hosts-sensor-tamper.json"
  uat_server_get "/api/hosts" "$body" || return 1
  local status
  status=$(jq -r --arg h "$UAT_HOST_ID" '.[]? | select(.host_id == $h) | .overall_status' "$body" 2>/dev/null)
  [[ "$status" == "healthy" ]]
}

# saw_transition reports whether the extension logged PROVIDER moving into the
# given state SINCE the tamper. A transition IS change-triggered, so the log is
# the right source here and the wrong one above.
#
# The window is anchored to TAMPER_AT rather than a rolling "--last 3m". A
# rolling window can still contain the "is running" line from BEFORE the
# tamper (the provider had to be running for the tamper to mean anything), so
# the recovery check would match that stale line and pass without any recovery
# having happened. TAMPER_AT is read from the VM's own clock, because a
# suspended VM resumes with a clock that can be well behind the host's and a
# host-side timestamp would silently select the wrong window.
saw_transition() {
  local want="$1"
  # sudo is load-bearing: `log show --info` only returns another process's
  # info-level messages to root, so an unprivileged read comes back EMPTY and
  # the assertion fails while the provider is behaving perfectly. See the
  # scenario README for the sudoers entry this needs.
  uat_ssh "$UAT_VM_SSH_TARGET" \
    "sudo log show --start '$TAMPER_AT' --info --predicate 'subsystem CONTAINS \"com.fleetdm\"' 2>/dev/null \
       | grep -qE 'Provider $PROVIDER $want'"
}

wait_for_transition() {
  local want="$1" timeout="$2" deadline
  deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < deadline )); do
    if saw_transition "$want"; then
      return 0
    fi
    sleep 3
  done
  return 1
}

uat_log sensor-tamper "confirming the host is capturing normally before tampering"
if ! host_is_healthy; then
  uat_log sensor-tamper "FAIL: host is not healthy to begin with; a tamper here would prove nothing"
  exit 1
fi

# The tamper itself. `disable-filter` is what an admin with root runs, and it
# is the same operation measured on a live host: the platform reports stop
# reason 1 (userInitiated), byte for byte what a routine extension cutover
# reports, which is why the rule discriminates on recovery latency instead.
# Anchor every subsequent log assertion to this instant, on the VM's clock.
TAMPER_AT=$(uat_ssh "$UAT_VM_SSH_TARGET" 'date "+%Y-%m-%d %H:%M:%S"')
if [[ -z "$TAMPER_AT" ]]; then
  uat_log sensor-tamper "FAIL: could not read the VM clock; log assertions would be unanchored"
  exit 1
fi

uat_log sensor-tamper "switching off $PROVIDER (log window anchored at $TAMPER_AT)"
uat_ssh "$UAT_VM_SSH_TARGET" "sudo '$EDR_CLI' disable-filter" || {
  uat_log sensor-tamper "FAIL: could not disable $PROVIDER"
  exit 1
}

uat_log sensor-tamper "waiting for the extension to report $PROVIDER stopped"
if ! wait_for_transition "stopped" "$STOP_TIMEOUT"; then
  uat_log sensor-tamper "FAIL: extension never reported $PROVIDER stopped, so no event can reach the server."
  uat_log sensor-tamper "      (If the provider was ALREADY off, disable-filter is a no-op and logs nothing.)"
  exit 1
fi
uat_log sensor-tamper "$PROVIDER reported stopped; the driver will poll for the alert"

# Wait out the repair before returning. Two reasons, and the second is the
# point of the whole rule: the VM must be left capturing for whatever runs
# next, AND an alert that survives the repair is the behaviour under test. The
# driver's poll window starts before this script runs, so the alert it finds
# afterwards is one that outlived the provider coming back.
uat_log sensor-tamper "waiting for the self-heal to restore $PROVIDER"
if ! wait_for_transition "is running" "$RECOVER_TIMEOUT"; then
  uat_log sensor-tamper "FAIL: $PROVIDER did not recover within ${RECOVER_TIMEOUT}s; VM left without capture"
  exit 1
fi

uat_log sensor-tamper "$PROVIDER restored; host healthy and the alert must still stand"
