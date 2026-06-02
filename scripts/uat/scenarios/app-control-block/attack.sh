#!/usr/bin/env bash
# L5 scenario: Application Control ACTIVE BLOCKING under SIP-on.
#
# Closes the coverage gap from the singleton-blocklist -> per-policy app-control
# rework (#289 / #290): the old /api/policy round-trip L5 scenario was removed
# and its replacement over /api/v1/app-control/* was "tracked separately". This
# is that replacement, and the missing half of the #301 acceptance gate
# ("Application Control still works", VM-validated).
#
# What it proves end to end on a real SIP + Gatekeeper VM:
#   1. A BINARY BLOCK rule POSTed via the admin REST API reaches the host as an
#      app-control snapshot (the agent /api/commands fan-out).
#   2. The system extension's AUTH_EXEC handler DENIES the matching exec -- the
#      binary that ran a moment ago now fails to exec (host-side enforcement).
#   3. The denial emits an application_control_block event -> server alert, which
#      the driver asserts via expected.yaml (rule_id=application_control_block).
#
# Receives from system-test.sh: UAT_VM_SSH_TARGET, UAT_HOST_ID, UAT_SCRIPT_DIR.
set -euo pipefail

# shellcheck source=/dev/null
source "$UAT_SCRIPT_DIR/lib/common.sh"
uat_server_warmup # populates UAT_COOKIE_HEADER + UAT_CSRF_TOKEN from EDR_SESSION_COOKIE
uat_curl_args     # populates UAT_CURL_ARGS (adds -k under UAT_INSECURE)

VM="$UAT_VM_SSH_TARGET"
TARGET=/tmp/edr-acblock-target
SRC=/tmp/edr-acblock-src
SENTINEL="EDR_ACBLOCK_SENTINEL_RAN"
RULE_ID=""
PLATFORM_RULE_ID=""

# rest METHOD PATH [JSON_BODY] -- authenticated admin REST call.
rest() {
  local method="$1" path="$2" body="${3:-}"
  # UAT_CURL_ARGS already carries --fail-with-body + -sS (+ -k under UAT_INSECURE);
  # do NOT re-add -f/-s here (-f conflicts with --fail-with-body).
  local args=("${UAT_CURL_ARGS[@]}" "${UAT_COOKIE_HEADER[@]}"
    -H "X-Csrf-Token: $UAT_CSRF_TOKEN" -X "$method" "$EDR_SERVER_URL$path")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" --data "$body")
  curl "${args[@]}"
}

cleanup() {
  # DeleteRule requires a reason in the JSON body (audit trail); a bodyless DELETE 400s.
  [[ -n "$RULE_ID" ]] && rest DELETE "/api/v1/app-control/rules/$RULE_ID" '{"reason":"uat app-control-block cleanup"}' >/dev/null 2>&1 || true
  # The platform carve-out probe rule (step 4b) is deleted inline on the happy path; this is the backstop if the script
  # exits between its create and that inline delete, so a stray BINARY rule on /bin/echo cannot leak into a later run.
  [[ -n "$PLATFORM_RULE_ID" ]] && rest DELETE "/api/v1/app-control/rules/$PLATFORM_RULE_ID" '{"reason":"uat platform carve-out probe cleanup"}' >/dev/null 2>&1 || true
  uat_ssh "$VM" "rm -rf $TARGET $SRC" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Build a deterministic, non-platform block target on the VM with `go build`
#    (the same trick the attack-runbook uses for its launchd dropper: a locally
#    compiled binary lacks Apple's is_platform_binary flag, so the unconditional
#    platform carve-out does NOT exempt it and a BINARY rule on its hash bites).
#    A copied system binary will not do: macOS binaries are arm64e, which AMFI
#    kills when run ad-hoc-signed outside SIP. Source is base64'd to dodge SSH
#    quoting. Hash the built binary -- that is the image that execs.
#
#    Go is a prerequisite on the VM (the attack-runbook scenario depends on it
#    too); fail with a clear message rather than a cryptic build error if it is
#    absent. See this scenario's README "Prerequisites".
uat_log app-control-block "building non-platform block target on VM (go build)"
if ! uat_ssh "$VM" "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin; command -v go >/dev/null"; then
  uat_fail app-control-block "go toolchain not found on the VM; this scenario needs it to build a non-platform block target (see README)"
fi
# Host base64 may line-wrap; tr strips that so the VM gets one token. Decode with
# -D (BSD-canonical, accepted on every macOS) rather than -d.
GO_SRC_B64=$(printf 'package main\nimport "fmt"\nfunc main(){ fmt.Println("%s") }\n' "$SENTINEL" | base64 | tr -d '\n')
uat_ssh "$VM" "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin
  mkdir -p $SRC
  echo '$GO_SRC_B64' | base64 -D > $SRC/main.go
  cd $SRC && go build -o $TARGET main.go"
HASH=$(uat_ssh "$VM" "shasum -a 256 $TARGET | awk '{print \$1}'")
[[ "$HASH" =~ ^[0-9a-f]{64}$ ]] || uat_fail app-control-block "could not build/hash block target (got '$HASH')"

# 2. Baseline: the target runs AND is allowed before the rule exists. Without
#    this, a later "did not run" reading could be an environment fault, not a block.
if ! uat_ssh "$VM" "$TARGET $SENTINEL" | grep -q "$SENTINEL"; then
  uat_fail app-control-block "baseline exec did not run; cannot distinguish allow from block"
fi
uat_log app-control-block "baseline exec allowed (sentinel printed) hash=${HASH:0:12}"

# 3. POST a BINARY BLOCK rule on that hash to the seeded Default policy.
POLICY_ID=$(rest GET /api/v1/app-control/policies | jq -r '.policies[] | select(.name=="Default") | .id' | head -1)
[[ -n "$POLICY_ID" && "$POLICY_ID" != "null" ]] || uat_fail app-control-block "could not resolve Default policy id"
RULE_ID=$(rest POST "/api/v1/app-control/policies/$POLICY_ID/rules" \
  "{\"rule_type\":\"BINARY\",\"identifier\":\"$HASH\",\"severity\":\"high\",\"custom_msg\":\"L5 app-control-block scenario\",\"reason\":\"uat app-control active-block coverage\"}" \
  | jq -r '.id')
[[ -n "$RULE_ID" && "$RULE_ID" != "null" ]] || uat_fail app-control-block "rule create did not return an id"
uat_log app-control-block "posted BINARY block rule id=$RULE_ID policy=$POLICY_ID; waiting for snapshot fan-out"

# 4. Poll: exec the target until the snapshot lands and the exec is DENIED. A
#    denied AUTH_EXEC fails to run, so the sentinel stops printing. Each denied
#    exec also emits an application_control_block event the driver asserts on.
blocked=0
deny_landed_iters=0
for i in {1..20}; do # ~60s; fan-out is normally single-digit seconds
  if ! uat_ssh "$VM" "$TARGET $SENTINEL 2>/dev/null" | grep -q "$SENTINEL"; then
    blocked=1
    deny_landed_iters=$i # record the observed fan-out latency to bound the platform-rule wait below
    break
  fi
  sleep 3
done
[[ "$blocked" == 1 ]] || uat_fail app-control-block "exec still ALLOWED after 60s; the BLOCK rule was not enforced"
# The block target is a locally `go build`-ed binary: it carries no kernel is_platform_binary flag, so the platform
# carve-out does NOT exempt it and the AUTH_EXEC handler proceeds to the snapshot precedence walk, where the BINARY
# rule on its SHA-256 matches and DENIES. A denied exec proves the snapshot was genuinely walked for a non-platform target.
# spec:extension-application-control/platform-binary-carve-out-precedes-the-snapshot-walk/a-non-platform-binary-still-walks-the-snapshot
uat_log app-control-block "host-side enforcement confirmed: matching exec is now DENIED"

# A couple more denied execs so the application_control_block alert is unambiguous.
uat_ssh "$VM" "$TARGET $SENTINEL >/dev/null 2>&1 || true; $TARGET $SENTINEL >/dev/null 2>&1 || true"

# 4b. Platform-binary carve-out: an Apple platform binary must be ALLOWed unconditionally even with a BINARY BLOCK rule
#     on its exact SHA-256. /bin/echo is on the Apple-signed system image, so the kernel sets is_platform_binary=true and
#     the AUTH_EXEC handler returns ALLOW (cache:true) BEFORE consulting the snapshot. We post a BINARY rule on echo's
#     hash, then confirm echo still runs -- the inverse of step 4. This is the carve-out that stops an admin from bricking
#     the host by blocklisting /sbin/launchd et al. A failure here (echo blocked) would be a host-bricking regression.
PLATFORM_BIN=/bin/echo
PLATFORM_SENTINEL="EDR_ACBLOCK_PLATFORM_OK"
PLATFORM_HASH=$(uat_ssh "$VM" "shasum -a 256 $PLATFORM_BIN | awk '{print \$1}'")
[[ "$PLATFORM_HASH" =~ ^[0-9a-f]{64}$ ]] || uat_fail app-control-block "could not hash platform binary $PLATFORM_BIN (got '$PLATFORM_HASH')"
PLATFORM_RULE_ID=$(rest POST "/api/v1/app-control/policies/$POLICY_ID/rules" \
  "{\"rule_type\":\"BINARY\",\"identifier\":\"$PLATFORM_HASH\",\"severity\":\"high\",\"custom_msg\":\"L5 platform carve-out probe\",\"reason\":\"uat app-control platform carve-out coverage\"}" \
  | jq -r '.id')
[[ -n "$PLATFORM_RULE_ID" && "$PLATFORM_RULE_ID" != "null" ]] || uat_fail app-control-block "platform-probe rule create did not return an id"
uat_log app-control-block "posted BINARY block rule id=$PLATFORM_RULE_ID on $PLATFORM_BIN (sha=${PLATFORM_HASH:0:12}); waiting for fan-out"

# Confirm echo STILL runs despite the block rule on its hash. echo's allow is carved out unconditionally, so we cannot poll
# for a positive "blocked" transition the way the deny poll above does -- the carve-out means echo never blocks. Instead we
# bound the wait by the fan-out latency the deny poll just measured (same policy, same fan-out path): wait that observed
# window plus a small margin for the new snapshot to land, then assert echo is allowed on several consecutive execs. This
# replaces an unconditional ~60s busy-wait (which ran the full budget on every happy path) with an observed-latency wait.
settle_iters=$(( deny_landed_iters + 2 ))
(( settle_iters < 4 )) && settle_iters=4 # floor so a near-instant deny landing still leaves a margin for the platform fan-out
for _ in $(seq 1 "$settle_iters"); do sleep 3; done
platform_allowed=1
for _ in {1..3}; do # echo must print its sentinel on every attempt once the snapshot carrying the block rule has landed
  if ! uat_ssh "$VM" "$PLATFORM_BIN $PLATFORM_SENTINEL 2>/dev/null" | grep -q "$PLATFORM_SENTINEL"; then
    platform_allowed=0
    break
  fi
  sleep 1
done
# spec:extension-application-control/platform-binary-carve-out-precedes-the-snapshot-walk/an-apple-platform-binary-is-unconditionally-allowed
[[ "$platform_allowed" == 1 ]] || uat_fail app-control-block "platform binary $PLATFORM_BIN was BLOCKED despite the carve-out (host-bricking regression)"
uat_log app-control-block "platform carve-out confirmed: $PLATFORM_BIN still ALLOWED with a BINARY block rule on its hash"
# Clean up the platform-probe rule so it cannot leak into a later run's snapshot.
rest DELETE "/api/v1/app-control/rules/$PLATFORM_RULE_ID" '{"reason":"uat platform carve-out probe cleanup"}' >/dev/null 2>&1 || true

# 5. Server-side assertion. The denial must surface as an application_control_block
#    alert. That alert's rule_id is app_control:<ruleId> -- DYNAMIC per run -- which
#    the driver's static expected.yaml cannot match, so attack.sh asserts it here
#    (the driver passes the scenario on attack.sh's exit 0; expected.yaml has no
#    rules block). Matching the exact app_control:$RULE_ID we just created also
#    rules out collapsing onto a stale alert from a prior run.
uat_log app-control-block "asserting application_control_block alert (rule_id=app_control:$RULE_ID)"
alert_seen=0
for _ in {1..15}; do # ~30s; event upload + detection is single-digit seconds
  if rest GET "/api/alerts?host_id=$UAT_HOST_ID&limit=100" |
    jq -e --arg rid "app_control:$RULE_ID" '.[]? | select(.rule_id==$rid and .source=="application_control")' >/dev/null 2>&1; then
    alert_seen=1
    break
  fi
  sleep 2
done
[[ "$alert_seen" == 1 ]] || uat_fail app-control-block "host blocked the exec but no application_control_block alert surfaced server-side"
uat_log app-control-block "server-side alert confirmed: app_control:$RULE_ID (source=application_control)"
uat_log app-control-block "PASS: host-side deny + server-side alert both confirmed"
