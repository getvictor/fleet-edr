#!/usr/bin/env bash
#
# scripts/uat/scenarios/network-containment/attack.sh
#
# L5 system test for host network containment (issues #948, #584). Contains the VM through the operator API, asserts on the
# VM what containment promises, then releases it and asserts the network is back.
#
# What it proves end to end, on a real host with the shipped agent and extensions:
#   1. POST /api/hosts/{host_id}/containment reaches the host, and the host confirms the state it applied, with a lifeline.
#   2. While contained, a new outbound connection elsewhere fails, a name other than the server's is answered REFUSED by the
#      DNS proxy, inbound SSH is refused, and the EDR server stays reachable.
#   3. The release is delivered to the contained host (so the lifeline carries the agent's command path), and afterwards the
#      host reaches the network and resolves names again.
#
# SSH is cut while the host is contained, so the VM cannot be asked anything in the middle of the test. A probe started on the
# VM before containment samples the network every few seconds into a log, and the log is read after the release. The samples
# are sorted into phases by the times this script saw each change confirmed, converted to the VM's clock.
#
# Contract with scripts/uat/system-test.sh:
#   UAT_VM_SSH_TARGET   ssh target (e.g. victor@192.168.64.7)
#   UAT_HOST_ID         the VM's host_id on the server
#   UAT_SCRIPT_DIR      scripts/uat/ absolute path
# EDR_SERVER_URL must be the URL the agent enrolled with, because the lifeline allows only the agent's own server endpoint.
#
# The scenario has no rules block: containment raises no alert, so it passes on this script's exit status alone.
#
# It never releases a containment it did not make. The host must be free when the run starts, the containment request must report
# that it changed the state, and the exit trap releases only while the host still carries the version this run created. An
# operator who contains the host in the moment between the check and the request keeps their containment, and the run stops.

set -eEuo pipefail

: "${UAT_VM_SSH_TARGET:?driver did not set UAT_VM_SSH_TARGET}"
: "${UAT_SCRIPT_DIR:?driver did not set UAT_SCRIPT_DIR}"
: "${UAT_HOST_ID:?driver did not set UAT_HOST_ID}"

# shellcheck disable=SC1091  # sourced path computed from UAT_SCRIPT_DIR; shellcheck cannot follow
. "$UAT_SCRIPT_DIR/lib/common.sh"
uat_server_warmup # UAT_COOKIE_HEADER + UAT_CSRF_TOKEN: arrays do not survive the environment, so each scenario warms up itself
uat_curl_args

TAG=network-containment
VM="$UAT_VM_SSH_TARGET"
RUN_DIR="/tmp/edr-uat-containment-$(date +%s)-$$"
PROBE_LOG="$RUN_DIR/probe.log"
PROBE_STOP="$RUN_DIR/stop"

# DELIVERY_TIMEOUT bounds how long the host takes to confirm a change: the command reaches an online agent within seconds over
# the control channel, and the agent completes it once the network extension reports the state applied.
DELIVERY_TIMEOUT=120
# HOLD_SECONDS is how long the host stays contained after it confirmed, so the probe takes several samples under containment.
HOLD_SECONDS=20
# SSH_RETURN_TIMEOUT bounds how long SSH takes to come back after the release is confirmed.
SSH_RETURN_TIMEOUT=60
# PROBE_MAX_SECONDS stops a probe this script never got to stop, so no run leaves a sampler behind.
PROBE_MAX_SECONDS=900
# OUTSIDE_URL is a destination the lifeline does not cover, by address so a DNS failure cannot stand in for a blocked connection.
OUTSIDE_URL="https://1.1.1.1/"
# OUTSIDE_NAME is a name that is not the server's, resolved with dig so the answer's status is visible.
OUTSIDE_NAME="example.com"
# CONTAIN_REASON identifies this run's containment on the state itself, for the case where the server applies a request whose
# response never arrives.
CONTAIN_REASON="uat network-containment"

containment() {
  uat_rest GET "/api/hosts/$UAT_HOST_ID/containment"
}

# request_state <true|false> <reason>: asks for a state and prints "<version> <changed>". `changed` is false when the host was
# already in the state asked for, which for a containment means someone else contained it first.
request_state() {
  local contained="$1" reason="$2" out
  if ! out=$(uat_rest POST "/api/hosts/$UAT_HOST_ID/containment" "{\"contained\":$contained,\"reason\":\"$reason\"}"); then
    uat_log "$TAG" "containment request refused: $out"
    uat_log "$TAG" "(reauth_required means EDR_SESSION_COOKIE's session authenticated longer ago than EDR_REAUTH_WINDOW)"
    return 1
  fi
  jq -r '"\(.state.version) \(.changed)"' <<<"$out"
}

# wait_for_delivery <version> <true|false>: waits for the host to complete the command carrying that version, and checks the
# result it reported. A failed command fails the scenario with the host's reason.
wait_for_delivery() {
  local version="$1" contained="$2" deadline state status
  deadline=$(( $(date +%s) + DELIVERY_TIMEOUT ))
  while (( $(date +%s) < deadline )); do
    state=$(containment) || state="{}"
    if [[ $(jq -r --argjson v "$version" '.version == $v and .delivery.current == true' <<<"$state") == "true" ]]; then
      status=$(jq -r '.delivery.status' <<<"$state")
      if [[ "$status" == "failed" ]]; then
        uat_log "$TAG" "the host failed version $version: $(jq -c '.delivery.result' <<<"$state")"
        return 1
      fi
      if [[ "$status" == "completed" ]]; then
        if [[ $(jq -r --argjson c "$contained" '.delivery.result.applied == true and .delivery.result.contained == $c' <<<"$state") != "true" ]]; then
          uat_log "$TAG" "version $version completed without applying contained=$contained: $(jq -c '.delivery.result' <<<"$state")"
          return 1
        fi
        LAST_STATE="$state"
        return 0
      fi
    fi
    sleep 2
  done
  uat_log "$TAG" "the host did not confirm version $version within ${DELIVERY_TIMEOUT}s: $(containment 2>/dev/null | jq -c '.delivery')"
  return 1
}

# OWNED_VERSION is the containment version this run created, while it is still in force: empty before the containment and once
# the release is confirmed. The exit trap releases only this.
OWNED_VERSION=""

# adopt_lost_containment handles a containment request whose response never arrived: the server may have applied it. The state
# carries the reason the request was made with, so a containment carrying this run's reason is this run's to release.
adopt_lost_containment() {
  local state
  state=$(containment 2>/dev/null) || return 0
  if [[ $(jq -r '.contained' <<<"$state") == "true" && $(jq -r '.reason // ""' <<<"$state") == "$CONTAIN_REASON" ]]; then
    OWNED_VERSION=$(jq -r '.version' <<<"$state")
    uat_log "$TAG" "the request failed but the host is contained with this run's reason, at version $OWNED_VERSION"
  fi
}

cleanup() {
  if [[ -n "$OWNED_VERSION" ]]; then
    local state version out
    state=$(containment 2>/dev/null) || state="{}"
    version=$(jq -r '.version // 0' <<<"$state")
    if [[ $(jq -r '.contained' <<<"$state") == "true" && "$version" == "$OWNED_VERSION" ]]; then
      uat_log "$TAG" "releasing the containment this run made"
      if out=$(request_state false "uat network-containment cleanup"); then
        wait_for_delivery "${out%% *}" false || uat_log "$TAG" "WARNING: the cleanup release was not confirmed; check the host"
      else
        uat_log "$TAG" "WARNING: the cleanup release was refused; release the host from its page"
      fi
    else
      uat_log "$TAG" "WARNING: not releasing: the host no longer carries this run's containment (version $version); check the host"
    fi
  fi
  uat_ssh "$VM" "touch $PROBE_STOP 2>/dev/null; sleep 3; rm -rf $RUN_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ssh_reaches_vm() {
  uat_ssh "$VM" true >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------

uat_log "$TAG" "checking the host is not contained"
BEFORE=$(containment)
if [[ $(jq -r '.contained' <<<"$BEFORE") != "false" ]]; then
  # Not this scenario's containment to lift: an operator may have contained the host for a reason.
  uat_fail "$TAG" "the host is already contained (reason: $(jq -r '.reason // ""' <<<"$BEFORE")); release it first"
fi

# The phases are cut on this script's clock and the samples are stamped on the VM's, so measure the difference once. A suspended
# VM can resume well behind the host.
HOST_NOW=$(date +%s)
VM_NOW=$(uat_ssh "$VM" 'date +%s')
CLOCK_OFFSET=$(( VM_NOW - HOST_NOW ))
uat_log "$TAG" "VM clock offset ${CLOCK_OFFSET}s"

# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

# A sample every few seconds: the outside destination's HTTP status (000 when the connection fails), the DNS status of a name
# that is not the server's (none when no answer came back), and the server's HTTP status over the lifeline. Each line carries the
# instant the sample started and the instant it finished, because the three probes take several seconds together and a sample
# that straddles a change belongs to neither state.
read -r -d '' PROBE <<'EOF' || true
out="$1"; stop="$2"; server="$3"; outside="$4"; name="$5"; max="$6"
end=$(( $(date +%s) + max ))
# Stop on the stop file, on the run directory going away (the script removes it, and it may not have been able to reach this host
# to write the stop file first), or at the deadline, so no run leaves a sampler behind.
while [ ! -e "$stop" ] && [ -d "$(dirname "$out")" ] && [ "$(date +%s)" -lt "$end" ]; do
  t=$(date +%s)
  o=$(curl -s -m 3 -o /dev/null -w '%{http_code}' "$outside" 2>/dev/null)
  d=$(dig +time=2 +tries=1 "$name" A 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
  s=$(curl -s -k -m 3 -o /dev/null -w '%{http_code}' "$server/livez" 2>/dev/null)
  echo "$t $(date +%s) outside=${o:-000} dns=${d:-none} server=${s:-000}" >> "$out"
  sleep 2
done
EOF
PROBE_B64=$(printf '%s\n' "$PROBE" | base64 | tr -d '\n')
uat_log "$TAG" "starting the probe on the VM"
uat_ssh "$VM" "mkdir -p $RUN_DIR && echo '$PROBE_B64' | base64 -D > $RUN_DIR/probe.sh && \
  nohup /bin/bash $RUN_DIR/probe.sh $PROBE_LOG $PROBE_STOP '$EDR_SERVER_URL' '$OUTSIDE_URL' '$OUTSIDE_NAME' $PROBE_MAX_SECONDS \
  > /dev/null 2>&1 < /dev/null &"
# Long enough for a few whole samples to land before the containment request, which is what proves the probe works at all.
sleep 14

# ---------------------------------------------------------------------------
# Contain
# ---------------------------------------------------------------------------

CONTAIN_AT=$(date +%s)
if ! CONTAIN_RESULT=$(request_state true "$CONTAIN_REASON"); then
  adopt_lost_containment
  uat_fail "$TAG" "the containment request did not succeed"
fi
CONTAIN_VERSION="${CONTAIN_RESULT%% *}"
if [[ "${CONTAIN_RESULT##* }" != "true" ]]; then
  # The host was free at the precondition and is contained now, so someone else contained it in between. Theirs to release.
  uat_fail "$TAG" "the host was contained by someone else between the check and the request; leaving their containment in place"
fi
OWNED_VERSION="$CONTAIN_VERSION"
uat_log "$TAG" "containment requested at version $CONTAIN_VERSION; waiting for the host to confirm"
wait_for_delivery "$CONTAIN_VERSION" true
CONTAINED_AT=$(date +%s)
LIFELINE=$(jq -c '.delivery.result.lifeline' <<<"$LAST_STATE")
uat_log "$TAG" "host confirmed containment after $(( CONTAINED_AT - CONTAIN_AT ))s, lifeline $LIFELINE"
if [[ $(jq -r 'length' <<<"$LIFELINE") -lt 1 ]]; then
  uat_fail "$TAG" "the host applied containment with an empty lifeline"
fi

sleep 3
if ssh_reaches_vm; then
  uat_fail "$TAG" "SSH still reaches the VM while it is contained"
fi
uat_log "$TAG" "SSH to the VM is refused while contained"
sleep "$HOLD_SECONDS"

# ---------------------------------------------------------------------------
# Release
# ---------------------------------------------------------------------------

RELEASE_AT=$(date +%s)
RELEASE_RESULT=$(request_state false "uat network-containment release")
RELEASE_VERSION="${RELEASE_RESULT%% *}"
uat_log "$TAG" "release requested at version $RELEASE_VERSION; waiting for the contained host to confirm"
wait_for_delivery "$RELEASE_VERSION" false
OWNED_VERSION=""
RELEASED_AT=$(date +%s)
uat_log "$TAG" "host confirmed the release after $(( RELEASED_AT - RELEASE_AT ))s"

deadline=$(( $(date +%s) + SSH_RETURN_TIMEOUT ))
until ssh_reaches_vm; do
  (( $(date +%s) < deadline )) || uat_fail "$TAG" "SSH did not come back within ${SSH_RETURN_TIMEOUT}s of the release"
  sleep 3
done
uat_log "$TAG" "SSH is back; letting the probe sample the released host"
sleep 10
uat_ssh "$VM" "touch $PROBE_STOP"
sleep 3
SAMPLES=$(uat_ssh "$VM" "cat $PROBE_LOG")

# ---------------------------------------------------------------------------
# Assert on the samples
# ---------------------------------------------------------------------------

# phase <from> <to>: the samples that both started and finished between two script-clock times, converted to the VM's clock. A
# sample overlapping either end is left out rather than judged against one state, since it observed both. The callers also keep a
# margin of PHASE_MARGIN around each change: the clock offset is measured in whole seconds over SSH, and the host applies a change
# a moment after the request returns.
phase() {
  local from=$(( $1 + CLOCK_OFFSET )) to=$(( $2 + CLOCK_OFFSET ))
  awk -v from="$from" -v to="$to" '$1 >= from && $2 <= to' <<<"$SAMPLES"
}

PHASE_MARGIN=3
BEFORE_SAMPLES=$(phase 0 $(( CONTAIN_AT - PHASE_MARGIN )))
CONTAINED_SAMPLES=$(phase $(( CONTAINED_AT + PHASE_MARGIN )) $(( RELEASE_AT - PHASE_MARGIN )))
AFTER_SAMPLES=$(phase $(( RELEASED_AT + PHASE_MARGIN )) 9999999999)

count() { grep -c . <<<"$1" || true; }
FAILED=0

# expect <label> <samples> <minimum> <pattern>: every sample in the phase matches the pattern, and there are enough of them. The
# before phase is what makes the contained assertions mean something: a probe that cannot reach the outside even when the host
# is free would otherwise pass every "blocked" check.
expect() {
  local label="$1" samples="$2" minimum="$3" pattern="$4" n bad
  n=$(count "$samples")
  if (( n < minimum )); then
    uat_log "$TAG" "FAIL $label: $n samples, need at least $minimum"
    FAILED=1
    return
  fi
  bad=$(grep -Ev "$pattern" <<<"$samples" || true)
  if [[ -n "$bad" ]]; then
    uat_log "$TAG" "FAIL $label: samples not matching /$pattern/:"
    printf '%s\n' "$bad" >&2
    FAILED=1
    return
  fi
  uat_log "$TAG" "ok $label ($n samples)"
}

expect "before containment the outside, DNS and the server all answer" "$BEFORE_SAMPLES" 2 \
  'outside=[1-5][0-9][0-9] dns=NOERROR server=[1-5][0-9][0-9]$'
expect "while contained the outside fails, other names are refused, the server answers" "$CONTAINED_SAMPLES" 3 \
  'outside=000 dns=REFUSED server=[1-5][0-9][0-9]$'
expect "after the release the outside and DNS answer again" "$AFTER_SAMPLES" 2 \
  'outside=[1-5][0-9][0-9] dns=NOERROR server=[1-5][0-9][0-9]$'

if (( FAILED == 1 )); then
  uat_log "$TAG" "all samples (VM clock; contain requested $(( CONTAIN_AT + CLOCK_OFFSET )), confirmed $(( CONTAINED_AT + CLOCK_OFFSET )), release requested $(( RELEASE_AT + CLOCK_OFFSET )), confirmed $(( RELEASED_AT + CLOCK_OFFSET ))):"
  printf '%s\n' "$SAMPLES" >&2
  exit 1
fi
uat_log "$TAG" "containment held and released as specified"
