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
# Rule-type coverage:
#   - BINARY     live: go-built binary, blocked by file SHA-256.
#   - PATH       live: blocked by canonical absolute path (server rewrites /tmp -> /private/tmp; the extension matches the same).
#   - CDHASH     live: ad-hoc + Hardened Runtime sign (CS_RUNTIME makes the extension surface the cdhash), blocked by cdhash.
#     These three use DISTINCT go binaries whose only matching identifier is the type under test, so the precedence ladder
#     (CDHASH > BINARY > CERTIFICATE > SIGNINGID > TEAMID > PATH) never lets one rule mask another. Rules accumulate; cleanup removes them.
#   - CERTIFICATE / SIGNINGID / TEAMID: the signing-derived types. They need a real Developer-ID-signed binary whose identity is
#     DISTINCT from the EDR's own (FDG8Q7N4CC) -- a CERTIFICATE rule on the EDR's shared leaf, or a TEAMID rule on its team,
#     would also deny the agent. Provide ONE such binary via UAT_ACBLOCK_FIXTURE_BIN (e.g. the 1Password CLI `op`, team
#     2BUA8C4S2C); the scenario derives all three identifiers from it and tests each in ISOLATION (post -> deny -> remove ->
#     allow-again) since the three share one binary. Skipped with a clear reason when unset. L0 cover: AuthExecDeciderPhaseBTests.
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
# The EDR's own Developer ID team. A CERTIFICATE/TEAMID fixture signed by this team would also match the agent + extension, so
# the fixture block refuses it. (Sourced from the extension's signing identity; see the XPC peer requirement in the extension.)
EDR_OWN_TEAM="FDG8Q7N4CC"

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
  # Remove the work tree (built binaries + the copied fixture) so the VM returns to a clean state for the next run.
  uat_ssh "$VM" "rm -rf $WORKDIR" >/dev/null 2>&1 || true
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

# post_block_rule <rule_type> <identifier> <label> -- POSTs a BLOCK rule on the Default policy and echoes the created rule id.
# high severity + a per-type custom_msg so an operator eyeballing the alert sees which probe fired.
post_block_rule() {
  local rule_type="$1" identifier="$2" label="$3" rid
  rid=$(rest POST "/api/v1/app-control/policies/$POLICY_ID/rules" \
    "{\"rule_type\":\"$rule_type\",\"identifier\":\"$identifier\",\"severity\":\"high\",\"custom_msg\":\"L5 app-control-block $label\",\"reason\":\"uat app-control $label coverage\"}" \
    | jq -r '.id')
  [[ -n "$rid" && "$rid" != "null" ]] || uat_fail app-control-block "$label: rule create did not return an id"
  # NOTE: this runs in the command-substitution subshell of probe_block; the RULE_IDS append for cleanup is done by the
  # PARENT-context caller (probe_block), since an append here would be lost when the subshell exits.
  echo "$rid"
}

# exec_ran <bin> <args> <mode> -- returns 0 if the exec RAN (allowed), non-zero if it was DENIED (blocked). Two liveness modes:
#   sentinel: the go targets echo $SENTINEL; "ran" = the sentinel appears in stdout (robust: proves the image actually ran).
#   exit:     a third-party fixture (e.g. `op`) does not echo our sentinel, so "ran" = the exec exits 0. A denied AUTH_EXEC
#             makes the exec fail (non-zero), so a clean exit 0 distinguishes allow from block.
exec_ran() {
  local bin="$1" runargs="$2" mode="$3"
  if [[ "$mode" == "sentinel" ]]; then
    uat_ssh "$VM" "$bin $runargs 2>/dev/null" | grep -q "$SENTINEL"
  else
    uat_ssh "$VM" "$bin $runargs >/dev/null 2>&1"
  fi
}

# wait_blocked <bin> <label> <args> <mode> -- polls the exec until the snapshot fan-out lands and the exec is DENIED. uat_fail
# on timeout. Fires a couple more denied execs so the application_control_block alert is unambiguous.
wait_blocked() {
  local bin="$1" label="$2" runargs="$3" mode="$4"
  for _ in $(seq 1 20); do # ~60s; fan-out is normally single-digit seconds
    if ! exec_ran "$bin" "$runargs" "$mode"; then
      uat_log app-control-block "$label: host-side enforcement confirmed -- matching exec is now DENIED"
      exec_ran "$bin" "$runargs" "$mode" >/dev/null 2>&1 || true
      exec_ran "$bin" "$runargs" "$mode" >/dev/null 2>&1 || true
      return 0
    fi
    sleep 3
  done
  uat_fail app-control-block "$label: exec still ALLOWED after ~60s; the BLOCK rule was not enforced"
}

# wait_allowed <bin> <label> <args> <mode> -- polls until the exec RUNS again. Used after an isolated probe removes its rule,
# to confirm the removal fanned out before the next probe so a lingering higher-precedence rule cannot mask it.
wait_allowed() {
  local bin="$1" label="$2" runargs="$3" mode="$4"
  for _ in $(seq 1 20); do
    if exec_ran "$bin" "$runargs" "$mode"; then
      return 0
    fi
    sleep 3
  done
  uat_fail app-control-block "$label: still BLOCKED ~60s after rule removal; probe isolation broke"
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

# probe_block <label> <rule_type> <identifier> <bin> <args> <mode> [isolate] -- the full per-type cycle: assert baseline-allowed,
# post the rule, wait for the host-side deny, assert the server-side alert. With a non-empty <isolate>, remove the rule and wait
# until the binary runs again -- required when several rule types share ONE binary (the signing-derived fixture) so the decider
# precedence does not let a lingering higher-precedence rule mask the next probe. Without it, the rule stays active (distinct go
# binaries never cross-match) and cleanup removes it.
probe_block() {
  local label="$1" rule_type="$2" identifier="$3" bin="$4" runargs="$5" mode="$6" isolate="${7:-}" rid
  if ! exec_ran "$bin" "$runargs" "$mode"; then
    uat_fail app-control-block "$label: baseline exec did not run; cannot distinguish allow from block"
  fi
  rid=$(post_block_rule "$rule_type" "$identifier" "$label")
  RULE_IDS+=("$rid") # parent-context append so cleanup() can delete every rule this run created
  uat_log app-control-block "$label: posted $rule_type rule id=$rid (identifier=${identifier:0:24}); waiting for snapshot fan-out"
  wait_blocked "$bin" "$label" "$runargs" "$mode"
  assert_alert "$rid" "$label"
  if [[ -n "$isolate" ]]; then
    rest DELETE "/api/v1/app-control/rules/$rid" '{"reason":"uat app-control isolate between probes"}' >/dev/null 2>&1 || true
    wait_allowed "$bin" "$label" "$runargs" "$mode"
    uat_log app-control-block "$label: rule removed; binary allowed again (isolated for the next probe)"
  fi
}

# ===========================================================================
# BINARY -- block by file SHA-256.
# ===========================================================================
BIN_BINARY=$(build_target binary)
HASH=$(uat_ssh "$VM" "shasum -a 256 $BIN_BINARY | awk '{print \$1}'")
[[ "$HASH" =~ ^[0-9a-f]{64}$ ]] || uat_fail app-control-block "BINARY: could not hash block target (got '$HASH')"
probe_block BINARY BINARY "$HASH" "$BIN_BINARY" "$SENTINEL" sentinel

# ===========================================================================
# PATH -- block by canonical absolute path. The server canonicalizes /tmp -> /private/tmp on persist and the extension
# canonicalizes the exec target the same way, so we POST the operator-facing /tmp path and exec via that same path.
# ===========================================================================
BIN_PATH=$(build_target path)
probe_block PATH PATH "$BIN_PATH" "$BIN_PATH" "$SENTINEL" sentinel

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
  probe_block CDHASH CDHASH "$CDHASH" "$BIN_CDHASH" "$SENTINEL" sentinel
else
  uat_fail app-control-block "CDHASH: could not extract a 40-hex cdhash from the signed binary (got '$CDHASH')"
fi

# ===========================================================================
# CERTIFICATE / SIGNINGID / TEAMID -- the signing-derived types, from ONE Developer-ID-signed fixture binary with a non-EDR
# identity. We derive its identifiers with READ-ONLY codesign on the host (never executing it here), copy the binary to the
# VM's /tmp (a file, NOT an install -- removed on cleanup), and exec it only on the VM. The three share one binary, so each is
# tested in isolation. A small CLI-safe binary works well: e.g. the 1Password CLI `op` (team 2BUA8C4S2C):
#   UAT_ACBLOCK_FIXTURE_BIN   absolute path on the HOST to a Developer-ID-signed binary with a non-EDR identity
#   UAT_ACBLOCK_FIXTURE_ARGS  args that make it exec-and-exit-0 cleanly (default: --version)
# ===========================================================================
if [[ -n "${UAT_ACBLOCK_FIXTURE_BIN:-}" ]]; then
  FX_ARGS="${UAT_ACBLOCK_FIXTURE_ARGS:---version}"
  [[ -f "$UAT_ACBLOCK_FIXTURE_BIN" ]] || uat_fail app-control-block "fixture binary not found on host: $UAT_ACBLOCK_FIXTURE_BIN"
  FX_TEAM=$(codesign -dvv "$UAT_ACBLOCK_FIXTURE_BIN" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2}')
  FX_IDENT=$(codesign -dvv "$UAT_ACBLOCK_FIXTURE_BIN" 2>&1 | awk -F= '/^Identifier=/{print $2}')
  [[ "$FX_TEAM" =~ ^[A-Z0-9]{10}$ ]] || uat_fail app-control-block "fixture is not Developer-ID-signed (TeamIdentifier='$FX_TEAM')"
  [[ "$FX_TEAM" != "$EDR_OWN_TEAM" ]] || uat_fail app-control-block "fixture team is the EDR's own ($EDR_OWN_TEAM); refusing -- a TEAMID/CERTIFICATE block would deny the agent. Use a binary from a different vendor."
  # Leaf cert SHA-256 = SHA-256 over the DER of the index-0 (leaf) cert. codesign writes DER files <prefix>0, <prefix>1, ...
  FX_CERTDIR=$(mktemp -d)
  codesign -d "--extract-certificates=$FX_CERTDIR/c" "$UAT_ACBLOCK_FIXTURE_BIN" >/dev/null 2>&1 || true
  FX_LEAF=$(shasum -a 256 "$FX_CERTDIR/c0" 2>/dev/null | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
  rm -rf "$FX_CERTDIR"
  [[ "$FX_LEAF" =~ ^[0-9a-f]{64}$ ]] || uat_fail app-control-block "could not derive fixture leaf cert sha256 (got '$FX_LEAF')"
  FX_SID="$FX_TEAM:$FX_IDENT"
  uat_log app-control-block "fixture: team=$FX_TEAM signing-id=$FX_SID leaf=${FX_LEAF:0:12}.. ($(basename "$UAT_ACBLOCK_FIXTURE_BIN"))"
  # Copy the signed binary to the VM (a /tmp file -- NOT an install) and make it executable.
  FX_VMBIN="$WORKDIR/fixture/fixture-bin"
  uat_ssh "$VM" "mkdir -p $WORKDIR/fixture"
  uat_scp "$UAT_ACBLOCK_FIXTURE_BIN" "$VM:$FX_VMBIN"
  uat_ssh "$VM" "chmod +x $FX_VMBIN"
  # Confirm the copied binary runs standalone on the VM before relying on it to distinguish allow from block.
  if ! exec_ran "$FX_VMBIN" "$FX_ARGS" exit; then
    uat_fail app-control-block "fixture did not run on the VM ('$(basename "$UAT_ACBLOCK_FIXTURE_BIN") $FX_ARGS'); pick a self-contained CLI or adjust UAT_ACBLOCK_FIXTURE_ARGS"
  fi
  probe_block CERTIFICATE CERTIFICATE "$FX_LEAF" "$FX_VMBIN" "$FX_ARGS" exit isolate
  probe_block SIGNINGID   SIGNINGID   "$FX_SID"  "$FX_VMBIN" "$FX_ARGS" exit isolate
  probe_block TEAMID      TEAMID      "$FX_TEAM" "$FX_VMBIN" "$FX_ARGS" exit isolate
else
  uat_log app-control-block "CERTIFICATE/SIGNINGID/TEAMID: SKIPPED -- set UAT_ACBLOCK_FIXTURE_BIN to a Developer-ID-signed binary with a non-EDR identity (e.g. the 1Password CLI 'op') to exercise the signing-derived rule types. L0 cover: AuthExecDeciderPhaseBTests."
fi

uat_log app-control-block "PASS: all enabled app-control block rule-type probes confirmed host-side deny + server-side alert"
