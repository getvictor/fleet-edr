#!/usr/bin/env bash
# L5 scenario: Application Control ACTIVE BLOCKING under SIP-on -- full rule-type matrix.
#
# Closes the coverage gap from the singleton-blocklist -> per-policy app-control rework (#289 / #290) and is the missing half
# of the #301 acceptance gate ("Application Control still works", VM-validated). Originally BINARY-only (#314); extended here to
# walk every block rule type the AUTH_EXEC decider supports (#210): CDHASH, BINARY, CERTIFICATE, SIGNINGID, TEAMID, PATH.
#
# What it proves end to end on a real SIP + Gatekeeper VM, once per rule type:
#   1. A BLOCK rule POSTed via the admin REST API reaches the host as an app-control snapshot (the agent /api/commands fan-out).
#   2. The system extension's AUTH_EXEC handler DENIES the matching exec -- a binary that ran a moment ago now fails to exec.
#   3. The denial emits an application_control_block event -> server alert, asserted here against the exact rule_id created.
#
# Each probe uses a DISTINCT binary whose only matching identifier is the one rule type under test, so the decider's precedence
# ladder (CDHASH > BINARY > CERTIFICATE > SIGNINGID > TEAMID > PATH) never lets one probe's rule mask another's. Rules accumulate
# in the Default policy and are all removed on exit.
#
# Rule-type coverage on a bare edr-qa (no Apple Developer ID fixtures):
#   - BINARY     live: go-built binary, blocked by file SHA-256.
#   - PATH       live: blocked by canonical absolute path (server rewrites /tmp -> /private/tmp; the extension matches the same).
#   - CDHASH     live: ad-hoc + Hardened Runtime sign (CS_RUNTIME makes the extension surface the cdhash), blocked by cdhash.
#   - CERTIFICATE gated: needs a fixture whose leaf cert SHA-256 is DISTINCT from the EDR's own Developer ID leaf (a rule on the
#                 shared leaf would also match the agent + extension). codesign only signs with a TRUSTED identity, so a self-signed
#                 leaf would require mutating the VM's system trust store -- not done on a release host. Set UAT_ACBLOCK_CERT_BIN +
#                 UAT_ACBLOCK_CERT_SHA256. L0 cover: AuthExecDeciderPhaseBTests.
#   - SIGNINGID  gated: needs a Developer-ID-signed fixture (team_id is only populated for Apple-issued certs; a self-signed cert
#                 yields none). Set UAT_ACBLOCK_SIGNINGID_BIN + UAT_ACBLOCK_SIGNINGID_ID to run. L0 cover: AuthExecDeciderPhaseBTests.
#   - TEAMID     gated + UNSAFE here: the only Developer-ID team available on this host is the EDR's own (FDG8Q7N4CC); a TEAMID
#                 block on it would also deny the agent. Needs a fixture signed by a DISTINCT team. L0 cover: AuthExecDeciderPhaseBTests.
#
# Receives from system-test.sh: UAT_VM_SSH_TARGET, UAT_HOST_ID, UAT_SCRIPT_DIR.
set -euo pipefail

# shellcheck source=/dev/null
source "$UAT_SCRIPT_DIR/lib/common.sh"
uat_server_warmup # populates UAT_COOKIE_HEADER + UAT_CSRF_TOKEN from EDR_SESSION_COOKIE
uat_curl_args     # populates UAT_CURL_ARGS (adds -k under UAT_INSECURE)

VM="$UAT_VM_SSH_TARGET"
# Per-run nonce so binaries, paths, and rule identifiers are unique across runs: a prior run's leftover rule (or a failed
# cleanup) can never collide into a 409 duplicate, and the work tree never clashes with a concurrent or stale run.
RUN_NONCE="$(date +%s)"
WORKDIR="/tmp/edr-acblock-$RUN_NONCE"
SENTINEL="EDR_ACBLOCK_SENTINEL_RAN"
# Indexed array (bash 3.2 safe -- macOS ships bash 3.2; no declare -A) of created rule ids, removed on exit.
RULE_IDS=()
POLICY_ID=""

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
  local rid
  for rid in "${RULE_IDS[@]:-}"; do
    [[ -n "$rid" ]] && rest DELETE "/api/v1/app-control/rules/$rid" '{"reason":"uat app-control-block cleanup"}' >/dev/null 2>&1 || true
  done
  # Remove the work tree (binaries + any temp keychain) so the VM returns to a clean state for the next run.
  uat_ssh "$VM" "security delete-keychain $WORKDIR/cert/uat.keychain-db >/dev/null 2>&1 || true; rm -rf $WORKDIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Prerequisites: go toolchain on the VM + the seeded Default policy id.
# ---------------------------------------------------------------------------
uat_log app-control-block "checking go toolchain on the VM"
if ! uat_ssh "$VM" "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin; command -v go >/dev/null"; then
  uat_fail app-control-block "go toolchain not found on the VM; this scenario needs it to build non-platform block targets (see README)"
fi
POLICY_ID=$(rest GET /api/v1/app-control/policies | jq -r '.policies[] | select(.name=="Default") | .id' | head -1)
[[ -n "$POLICY_ID" && "$POLICY_ID" != "null" ]] || uat_fail app-control-block "could not resolve Default policy id"
uat_log app-control-block "Default policy id=$POLICY_ID"

# build_target <subdir> -- builds a unique, non-platform go binary at $WORKDIR/<subdir>/target on the VM and echoes its path.
# A locally compiled binary lacks Apple's is_platform_binary flag, so the platform carve-out does not exempt it. Source is
# base64'd to dodge SSH quoting; decoded with -D (BSD-canonical, accepted on every macOS). Each subdir gets a unique sentinel
# arg via main(args) so the binaries are content-distinct (distinct SHA-256 / cdhash) without per-build source edits.
build_target() {
  local subdir="$1" dir="$WORKDIR/$1" src_b64
  src_b64=$(printf 'package main\nimport (\n"fmt"\n"os"\n)\nfunc main(){ a:="%s"; if len(os.Args)>1 { a=os.Args[1] }; fmt.Println(a) }\n' "$SENTINEL-$subdir-$RUN_NONCE" | base64 | tr -d '\n')
  uat_ssh "$VM" "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin
    mkdir -p $dir
    echo '$src_b64' | base64 -D > $dir/main.go
    cd $dir && go build -o $dir/target main.go" >/dev/null
  echo "$dir/target"
}

# post_block_rule <rule_type> <identifier> <label> -- POSTs a BLOCK rule on the Default policy and records the id for cleanup.
# Echoes the created rule id. high severity + a per-type custom_msg so an operator eyeballing the alert sees which probe fired.
post_block_rule() {
  local rule_type="$1" identifier="$2" label="$3" rid
  rid=$(rest POST "/api/v1/app-control/policies/$POLICY_ID/rules" \
    "{\"rule_type\":\"$rule_type\",\"identifier\":\"$identifier\",\"severity\":\"high\",\"custom_msg\":\"L5 app-control-block $label\",\"reason\":\"uat app-control $label coverage\"}" \
    | jq -r '.id')
  [[ -n "$rid" && "$rid" != "null" ]] || uat_fail app-control-block "$label: rule create did not return an id"
  # NOTE: this runs in the command-substitution subshell of probe_block; the RULE_IDS append for cleanup is done by the
  # PARENT-context caller (probe_block) below, since an append here would be lost when the subshell exits.
  echo "$rid"
}

# wait_blocked <binary_path> <label> -- polls the exec until the snapshot fan-out lands and the exec is DENIED (the sentinel
# stops printing). uat_fail on timeout. A denied AUTH_EXEC also emits the application_control_block event asserted next.
wait_blocked() {
  local bin="$1" label="$2"
  for _ in $(seq 1 20); do # ~60s; fan-out is normally single-digit seconds
    if ! uat_ssh "$VM" "$bin $SENTINEL 2>/dev/null" | grep -q "$SENTINEL"; then
      uat_log app-control-block "$label: host-side enforcement confirmed -- matching exec is now DENIED"
      # A couple more denied execs so the alert is unambiguous.
      uat_ssh "$VM" "$bin $SENTINEL >/dev/null 2>&1 || true; $bin $SENTINEL >/dev/null 2>&1 || true"
      return 0
    fi
    sleep 3
  done
  uat_fail app-control-block "$label: exec still ALLOWED after ~60s; the BLOCK rule was not enforced"
}

# assert_alert <rule_id> <label> -- polls the server until the application_control_block alert for app_control:<rule_id> appears.
assert_alert() {
  local rid="$1" label="$2"
  for _ in $(seq 1 15); do # ~30s; event upload + detection is single-digit seconds
    if rest GET "/api/alerts?host_id=$UAT_HOST_ID&limit=200" |
      jq -e --arg rid "app_control:$rid" '.[]? | select(.rule_id==$rid and .source=="application_control")' >/dev/null 2>&1; then
      uat_log app-control-block "$label: server-side alert confirmed (rule_id=app_control:$rid, source=application_control)"
      return 0
    fi
    sleep 2
  done
  uat_fail app-control-block "$label: host blocked the exec but no application_control_block alert surfaced server-side"
}

# probe_block <label> <rule_type> <identifier> <binary_path> -- the full per-type cycle: assert baseline-allowed, post the rule,
# wait for the host-side deny, assert the server-side alert. Leaves the rule active (cleanup removes it); distinct identifiers
# mean an accumulated rule never masks a later probe.
probe_block() {
  local label="$1" rule_type="$2" identifier="$3" bin="$4" rid
  if ! uat_ssh "$VM" "$bin $SENTINEL" | grep -q "$SENTINEL"; then
    uat_fail app-control-block "$label: baseline exec did not run; cannot distinguish allow from block"
  fi
  rid=$(post_block_rule "$rule_type" "$identifier" "$label")
  RULE_IDS+=("$rid") # parent-context append so cleanup() can delete every rule this run created
  uat_log app-control-block "$label: posted $rule_type rule id=$rid; waiting for snapshot fan-out"
  wait_blocked "$bin" "$label"
  assert_alert "$rid" "$label"
}

# ===========================================================================
# BINARY -- block by file SHA-256.
# ===========================================================================
BIN_BINARY=$(build_target binary)
HASH=$(uat_ssh "$VM" "shasum -a 256 $BIN_BINARY | awk '{print \$1}'")
[[ "$HASH" =~ ^[0-9a-f]{64}$ ]] || uat_fail app-control-block "BINARY: could not hash block target (got '$HASH')"
probe_block BINARY BINARY "$HASH" "$BIN_BINARY"

# ===========================================================================
# PATH -- block by canonical absolute path. The server canonicalizes /tmp -> /private/tmp on persist and the extension
# canonicalizes the exec target the same way, so we POST the operator-facing /tmp path and exec via that same path.
# ===========================================================================
BIN_PATH=$(build_target path)
probe_block PATH PATH "$BIN_PATH" "$BIN_PATH"

# ===========================================================================
# CDHASH -- block by code-directory hash. The extension only surfaces the cdhash when the target runs under Hardened Runtime
# (CS_RUNTIME), so we ad-hoc sign WITH -o runtime. Ad-hoc signing needs no identity, so this is safe + Apple-ID-free. The
# cdhash is unique to this binary, so the rule matches nothing else.
# ===========================================================================
BIN_CDHASH=$(build_target cdhash)
uat_ssh "$VM" "codesign -s - -f -o runtime --identifier com.fleetdm.edr.uat-cdhash-probe $BIN_CDHASH" >/dev/null 2>&1 \
  || uat_fail app-control-block "CDHASH: ad-hoc + hardened-runtime codesign failed"
CDHASH=$(uat_ssh "$VM" "codesign -d -vvv $BIN_CDHASH 2>&1 | awk -F= '/^CDHash=/{print \$2}' | tr '[:upper:]' '[:lower:]'")
if [[ "$CDHASH" =~ ^[0-9a-f]{40}$ ]]; then
  probe_block CDHASH CDHASH "$CDHASH" "$BIN_CDHASH"
else
  uat_fail app-control-block "CDHASH: could not extract a 40-hex cdhash from the signed binary (got '$CDHASH')"
fi

# ===========================================================================
# CERTIFICATE -- gated. Block by leaf signing-cert SHA-256. A SAFE probe needs a binary whose leaf cert is DISTINCT from the
# EDR's own Developer ID leaf -- a CERTIFICATE rule on the shared leaf would also match the agent + extension. A self-signed
# identity would give a distinct leaf, but codesign only signs with a TRUSTED identity, and trusting a throwaway root would
# modify this release-validation VM's system trust store (verified: import succeeds but `codesign -s` reports "no identity
# found" and falls back to ad-hoc until the cert is trusted). We deliberately do not mutate the VM trust store. Provide a
# pre-signed fixture to run:
#   UAT_ACBLOCK_CERT_BIN     absolute path to a signed binary on the VM whose leaf cert is NOT the EDR's
#   UAT_ACBLOCK_CERT_SHA256  that leaf cert's SHA-256 (64 lowercase hex; e.g. codesign -d --extract-certificates + shasum -a 256)
# ===========================================================================
if [[ -n "${UAT_ACBLOCK_CERT_BIN:-}" && -n "${UAT_ACBLOCK_CERT_SHA256:-}" ]]; then
  probe_block CERTIFICATE CERTIFICATE "$UAT_ACBLOCK_CERT_SHA256" "$UAT_ACBLOCK_CERT_BIN"
else
  uat_log app-control-block "CERTIFICATE: SKIPPED -- needs a fixture whose leaf cert sha256 differs from the EDR's own Developer ID leaf (a self-signed identity would require trusting a root in the VM's system store). Set UAT_ACBLOCK_CERT_BIN + UAT_ACBLOCK_CERT_SHA256. L0 cover: AuthExecDeciderPhaseBTests."
fi

# ===========================================================================
# SIGNINGID -- gated. signingID matching needs a real Apple team_id (kSecCodeInfoTeamIdentifier is populated only for
# Apple-issued certs; a self-signed cert yields none), so it needs a Developer-ID-signed fixture. The match key is
# "<TeamID>:<bundle.id>", so a unique bundle id makes the block match only the fixture (safe). Provide a pre-signed binary:
#   UAT_ACBLOCK_SIGNINGID_BIN  absolute path to a Developer-ID-signed binary already on the VM
#   UAT_ACBLOCK_SIGNINGID_ID   its signing id, e.g. FDG8Q7N4CC:com.example.uat-probe
# ===========================================================================
if [[ -n "${UAT_ACBLOCK_SIGNINGID_BIN:-}" && -n "${UAT_ACBLOCK_SIGNINGID_ID:-}" ]]; then
  probe_block SIGNINGID SIGNINGID "$UAT_ACBLOCK_SIGNINGID_ID" "$UAT_ACBLOCK_SIGNINGID_BIN"
else
  uat_log app-control-block "SIGNINGID: SKIPPED -- needs a Developer-ID-signed fixture (set UAT_ACBLOCK_SIGNINGID_BIN + UAT_ACBLOCK_SIGNINGID_ID). L0 cover: AuthExecDeciderPhaseBTests."
fi

# ===========================================================================
# TEAMID -- gated + UNSAFE on this host. A TEAMID block matches EVERY binary signed by that team. The only Developer-ID team
# available here is the EDR's own (FDG8Q7N4CC), and blocking it would also deny the agent + extension. A safe TEAMID probe
# needs a fixture signed by a team DISTINCT from the EDR's. Provide one explicitly to run:
#   UAT_ACBLOCK_TEAMID_BIN  absolute path to a binary signed by a non-EDR Developer-ID team, on the VM
#   UAT_ACBLOCK_TEAMID_ID   that team id (10 uppercase alphanumeric)
# ===========================================================================
if [[ -n "${UAT_ACBLOCK_TEAMID_BIN:-}" && -n "${UAT_ACBLOCK_TEAMID_ID:-}" ]]; then
  probe_block TEAMID TEAMID "$UAT_ACBLOCK_TEAMID_ID" "$UAT_ACBLOCK_TEAMID_BIN"
else
  uat_log app-control-block "TEAMID: SKIPPED -- the only Developer-ID team on this host is the EDR's own (FDG8Q7N4CC); blocking it would deny the agent. Needs a distinct-team fixture (UAT_ACBLOCK_TEAMID_BIN + UAT_ACBLOCK_TEAMID_ID). L0 cover: AuthExecDeciderPhaseBTests."
fi

uat_log app-control-block "PASS: all enabled app-control block rule-type probes confirmed host-side deny + server-side alert"
