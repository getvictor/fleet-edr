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
# It never releases a containment it did not make. The host's containment is one versioned state that anyone may change while the
# run is in flight, so each moment an operator could change it is answered:
#
#   before the request      the run stops if the host is already contained, and says whose reason it carries.
#   during the request      the request must report that it changed the state. A host contained by someone else in that moment
#                           answers changed=false, and the run stops rather than adopting their containment.
#   response lost           the state carries the reason the request was made with, tagged per run, so a containment this run
#                           caused is still this run's to release.
#   during the hold         both releases, the normal one and the trap's, read the state first and release only while the host
#                           still carries the version this run created.
#   during a release        unclosable here: the read and the request are two calls, and the request cannot name the version it
#                           expects (#1076). One round trip wide, against a hold of tens of seconds.

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
RUN_TAG="$(date +%s)-$$"
RUN_DIR="/tmp/edr-uat-containment-$RUN_TAG"
PROBE_LOG="$RUN_DIR/probe.log"
PROBE_STOP="$RUN_DIR/stop"

# DELIVERY_TIMEOUT bounds how long the host takes to confirm a change: the command reaches an online agent within seconds over
# the control channel, and the agent completes it once the network extension reports the state applied.
DELIVERY_TIMEOUT=120
# HOLD_SECONDS is how long the host stays contained after it confirmed. The other phases wait for the samples they need, which
# this one cannot do: SSH is cut while the host is contained, so the log cannot be read until afterwards. The window is the hold
# plus the SSH-refusal check, less the margin at each end, so about 39s; at the probe's worst case of a sample every 8s that is
# still 4 whole samples, and measured on edr-dev it is 17, because a dropped connection fails immediately rather than timing out.
HOLD_SECONDS=30
# SSH_RETURN_TIMEOUT bounds how long SSH takes to come back after the release is confirmed.
SSH_RETURN_TIMEOUT=60
# PROBE_MAX_SECONDS stops a probe this script never got to stop, so no run leaves a sampler behind.
PROBE_MAX_SECONDS=900
# OUTSIDE_URL is a destination the lifeline does not cover, by address so a DNS failure cannot stand in for a blocked connection.
OUTSIDE_URL="https://1.1.1.1/"
# OUTSIDE_NAME is a name that is not the server's, resolved with dig so the answer's status is visible.
OUTSIDE_NAME="example.com"
# PHASE_MARGIN is how far from each change a sample is ignored, covering the whole-second clock offset and the moment between the
# request returning and the host applying it.
PHASE_MARGIN=3
# How many whole samples each phase needs. The before phase is the one that gives the others meaning, so it is not zero.
MIN_BEFORE=2
MIN_CONTAINED=3
MIN_AFTER=2
# SAMPLE_WAIT_TIMEOUT bounds waiting for the samples a phase needs, so a probe that is not sampling fails the run rather than
# hanging it. A sample takes about two seconds here and under eight in the probe's worst case, where every request waits out its
# own timeout.
SAMPLE_WAIT_TIMEOUT=90
# CONTAIN_REASON identifies this run's containment on the state itself, for the case where the server applies a request whose
# response never arrives. The per-run tag keeps it this run's own, so two runs against one host cannot adopt each other's.
CONTAIN_REASON="uat network-containment $RUN_TAG"

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
      # failed is the host's own refusal; cancelled and expired are the server withdrawing or ageing out the command. All three
      # are terminal for this version, so waiting out the timeout would only delay the report.
      if [[ "$status" == "failed" || "$status" == "cancelled" || "$status" == "expired" ]]; then
        uat_log "$TAG" "version $version ended $status: $(jq -c '.delivery.result' <<<"$state")"
        return 1
      fi
      if [[ "$status" == "completed" ]]; then
        local applied
        applied=$(jq -r --argjson c "$contained" '.delivery.result.applied == true and .delivery.result.contained == $c' <<<"$state")
        if [[ "$applied" != "true" ]]; then
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

# release_owned <reason>: releases only while the host still carries the containment this run made, and prints the version the
# release was recorded at. It reads the state immediately before asking, so an operator who took the host over in the meantime
# keeps their containment.
#
# The read and the request are two calls, so an operator who releases and re-contains between them is released by this run
# anyway. Closing that needs the request to carry the version it expects, which the API does not offer yet (#1076). The window
# is the round trip of one request, against a hold of tens of seconds, and every wider window is checked.
release_owned() {
  local reason="$1" state version out
  state=$(containment 2>/dev/null) || state="{}"
  version=$(jq -r '.version // 0' <<<"$state")
  if [[ $(jq -r '.contained' <<<"$state") != "true" || "$version" != "$OWNED_VERSION" ]]; then
    uat_log "$TAG" "WARNING: not releasing: the host no longer carries this run's containment (version $version); check the host"
    return 1
  fi
  out=$(request_state false "$reason") || return 1
  echo "${out%% *}"
}

cleanup() {
  if [[ -n "$OWNED_VERSION" ]]; then
    local version
    uat_log "$TAG" "releasing the containment this run made"
    if version=$(release_owned "uat network-containment cleanup $RUN_TAG"); then
      wait_for_delivery "$version" false || uat_log "$TAG" "WARNING: the cleanup release was not confirmed; check the host"
    else
      uat_log "$TAG" "WARNING: the cleanup release did not go through; check the host"
    fi
  fi
  uat_ssh "$VM" "touch $PROBE_STOP 2>/dev/null; sleep 3; rm -rf $RUN_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ssh_reaches_vm() {
  uat_ssh "$VM" true >/dev/null 2>&1
}

# wait_for_samples <count> <what> [since]: waits until the probe log holds <count> samples, or those starting at or after <since>
# on the VM's clock. Reads the log over SSH, so it is only usable while the host is reachable.
wait_for_samples() {
  local want="$1" what="$2" since="${3:-0}" deadline have
  deadline=$(( $(date +%s) + SAMPLE_WAIT_TIMEOUT ))
  while :; do
    have=$(uat_ssh "$VM" "awk '\$1 >= $since' $PROBE_LOG 2>/dev/null | wc -l" | tr -dc '0-9')
    [[ -n "$have" ]] || have=0
    (( have >= want )) && return 0
    if (( $(date +%s) >= deadline )); then
      uat_fail "$TAG" "waited ${SAMPLE_WAIT_TIMEOUT}s for $what and got $have; is the probe running?"
    fi
    sleep 2
  done
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
# The local clock is read on both sides of the remote one, so the offset is the difference from the midpoint rather than one that
# has absorbed the SSH round trip. Only the last line of the reply is taken, and it must be a bare timestamp: a login banner
# would otherwise contribute its own digits, and stripping non-digits from the whole reply would splice them into the number.
HOST_BEFORE=$(date +%s)
VM_NOW=$(uat_ssh "$VM" 'date +%s' | tr -d '\r' | tail -1)
HOST_AFTER=$(date +%s)
[[ "$VM_NOW" =~ ^[0-9]+$ ]] || uat_fail "$TAG" "the VM clock read back as \"$VM_NOW\"; the samples could not be placed in a phase"
ROUND_TRIP=$(( HOST_AFTER - HOST_BEFORE ))
if (( ROUND_TRIP > PHASE_MARGIN )); then
  # Beyond the margin the midpoint is not accurate enough to say which side of a change a sample falls on.
  uat_fail "$TAG" "reading the VM clock took ${ROUND_TRIP}s, more than the ${PHASE_MARGIN}s margin the phases rely on"
fi
CLOCK_OFFSET=$(( VM_NOW - (HOST_BEFORE + HOST_AFTER) / 2 ))
uat_log "$TAG" "VM clock offset ${CLOCK_OFFSET}s, read in ${ROUND_TRIP}s"

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
  # Status and answer count together: NOERROR alone can carry an empty answer section, which would pass for resolution.
  dig_out=$(dig +time=2 +tries=1 "$name" A 2>/dev/null)
  d=$(printf '%s' "$dig_out" | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
  a=$(printf '%s' "$dig_out" | sed -n 's/.*ANSWER: \([0-9]*\).*/\1/p')
  s=$(curl -s -k -m 3 -o /dev/null -w '%{http_code}' "$server/livez" 2>/dev/null)
  echo "$t $(date +%s) outside=${o:-000} dns=${d:-none}/${a:-0} server=${s:-000}" >> "$out"
  sleep 2
done
EOF
PROBE_B64=$(printf '%s\n' "$PROBE" | base64 | tr -d '\n')
uat_log "$TAG" "starting the probe on the VM"
uat_ssh "$VM" "mkdir -p $RUN_DIR && echo '$PROBE_B64' | base64 -D > $RUN_DIR/probe.sh && \
  nohup /bin/bash $RUN_DIR/probe.sh $PROBE_LOG $PROBE_STOP '$EDR_SERVER_URL' '$OUTSIDE_URL' '$OUTSIDE_NAME' $PROBE_MAX_SECONDS \
  > /dev/null 2>&1 < /dev/null &"
# Wait for the samples the before phase needs rather than assuming a duration: a slow host takes longer per sample, and a run
# that failed for want of a baseline sample would say nothing about containment. The margin then puts them wholly before the
# request.
wait_for_samples "$MIN_BEFORE" "the probe to take $MIN_BEFORE samples of the free host"
sleep "$PHASE_MARGIN"

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
RELEASE_VERSION=$(release_owned "uat network-containment release $RUN_TAG") \
  || uat_fail "$TAG" "the release did not go through; see the warning above"
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
uat_log "$TAG" "SSH is back; waiting for the probe to sample the released host"
wait_for_samples "$MIN_AFTER" "$MIN_AFTER samples of the released host" \
  "$(( RELEASED_AT + CLOCK_OFFSET + PHASE_MARGIN ))"
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

BEFORE_SAMPLES=$(phase 0 $(( CONTAIN_AT - PHASE_MARGIN )))
CONTAINED_SAMPLES=$(phase $(( CONTAINED_AT + PHASE_MARGIN )) $(( RELEASE_AT - PHASE_MARGIN )))
AFTER_SAMPLES=$(phase $(( RELEASED_AT + PHASE_MARGIN )) 9999999999)

count() {
  local samples="$1"
  grep -c . <<<"$samples" || true
}
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

expect "before containment the outside, DNS and the server all answer" "$BEFORE_SAMPLES" "$MIN_BEFORE" \
  'outside=[1-5][0-9][0-9] dns=NOERROR/[1-9][0-9]* server=[1-5][0-9][0-9]$'
expect "while contained the outside fails, other names are refused, the server answers" "$CONTAINED_SAMPLES" "$MIN_CONTAINED" \
  'outside=000 dns=REFUSED/0 server=[1-5][0-9][0-9]$'
expect "after the release the outside and DNS answer again" "$AFTER_SAMPLES" "$MIN_AFTER" \
  'outside=[1-5][0-9][0-9] dns=NOERROR/[1-9][0-9]* server=[1-5][0-9][0-9]$'

if (( FAILED == 1 )); then
  uat_log "$TAG" "contain requested $(( CONTAIN_AT + CLOCK_OFFSET )), confirmed $(( CONTAINED_AT + CLOCK_OFFSET )); release" \
    "requested $(( RELEASE_AT + CLOCK_OFFSET )), confirmed $(( RELEASED_AT + CLOCK_OFFSET )) (VM clock). All samples:"
  printf '%s\n' "$SAMPLES" >&2
  exit 1
fi
uat_log "$TAG" "containment held and released as specified"
