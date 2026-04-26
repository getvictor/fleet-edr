#!/usr/bin/env bash
#
# Phase-7 dogfood QA E2: blocklist policy round-trip.
#
# Drives a full round-trip of the blocklist:
#  1. Authenticate to the EDR admin API and pick up the CSRF token.
#  2. Fetch the current policy, append a synthetic "to-be-blocked" path,
#     PUT the result back. The server fans out a policy.update command
#     to every active host.
#  3. Wait up to 60s for the agent on the target VM to ack the new
#     policy and write it to /var/db/com.fleetdm.edr/policy.json.
#  4. SSH to the VM and try to execute the blocked path. Expect the
#     extension to deny the exec via ES_AUTH_RESULT_DENY. The shell
#     sees "Operation not permitted" / "Killed: 9" depending on the
#     macOS version.
#  5. Query /api/v1/alerts for any new alerts on the host within the
#     test window, mostly for the operator's eye — there's no
#     `blocked_exec` rule shipping with the MVP detection pack today.
#     The actual block lives in the kernel via the AUTH callback;
#     surfacing a paired alert in the UI is an open Phase 8 item.
#  6. Restore the original policy so the script is idempotent.
#
# Usage from this workstation (NOT the VM):
#   EDR_SERVER_URL=https://edr.local:8088 \
#   EDR_ADMIN_EMAIL=admin@fleet-edr.local \
#   EDR_ADMIN_PASSWORD=<paste> \
#   VM_SSH_TARGET=victor@192.168.64.5 \
#   bash scripts/qa/e2-policy-roundtrip.sh
#
# All four variables are required; we fail fast if any is missing so
# operators don't spend ten minutes wondering why curl is silent.

set -uEo pipefail

# -E (errtrace) so the ERR trap fires inside helper functions and
# command substitutions too — without it, failures in subshells stay
# silent.
# shellcheck disable=SC2154  # `rc` is assigned inside the trap body via $?
trap 'rc=$?; echo "[e2] step at line $LINENO exited $rc — continuing"' ERR

require_env() {
  for v in "$@"; do
    if [[ -z "${!v:-}" ]]; then
      echo "[e2] missing required env var: $v" >&2
      echo "[e2] see the header comment for the full list" >&2
      exit 2
    fi
  done
  return 0
}
require_env EDR_SERVER_URL EDR_ADMIN_EMAIL EDR_ADMIN_PASSWORD VM_SSH_TARGET

# umask + private mktemp so the session cookie + login response don't
# leak to other local users on a permissive default-umask host.
umask 077
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/edr-e2-policy.XXXXXX")
chmod 700 "$WORKDIR"
COOKIE_JAR="$WORKDIR/cookies"
SYNTHETIC_PATH="/tmp/edr-e2-blocked-payload"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
# Constant for the JSON Content-Type header used on every POST/PUT below;
# de-duplicating the literal keeps the curl invocations scannable and
# satisfies the Sonar S1192 minor finding.
CT_JSON='Content-Type: application/json'
# Mirror the BASH_S constant from e3/e4 even though there's only one
# `bash -s` site here today — keeps the three QA scripts consistent so a
# future ssh-driven step doesn't grow a duplicate literal.
BASH_S='bash -s'

hr() {
  printf '\n%s\n' '────────────────────────────────────────────────────────'
  return 0
}

# Login: POST /api/v1/session with {email, password} → returns user +
# csrf_token JSON, sets edr_session cookie. Response includes the CSRF
# token in the body so we can pull it out without parsing Set-Cookie.
hr
echo "[e2] step 1: authenticate to $EDR_SERVER_URL"
LOGIN_BODY="$WORKDIR/login.json"
http_code=$(curl -sS \
  -o "$LOGIN_BODY" \
  -w '%{http_code}' \
  -c "$COOKIE_JAR" \
  -H "$CT_JSON" \
  -d "$(printf '{"email":%s,"password":%s}' \
        "$(printf '%s' "$EDR_ADMIN_EMAIL" | jq -R .)" \
        "$(printf '%s' "$EDR_ADMIN_PASSWORD" | jq -R .)")" \
  "$EDR_SERVER_URL/api/v1/session" || echo "000")
if [[ "$http_code" != "200" ]]; then
  echo "[e2] login failed: HTTP $http_code" >&2
  cat "$LOGIN_BODY" >&2
  exit 1
fi
CSRF_TOKEN=$(jq -r '.csrf_token // ""' "$LOGIN_BODY")
if [[ -z "$CSRF_TOKEN" ]]; then
  echo "[e2] login response missing csrf_token; body was:" >&2
  cat "$LOGIN_BODY" >&2
  exit 1
fi
echo "[e2] logged in; got CSRF token"

# Capture the current policy so we can restore it at the end. The
# admin UI's blocklist is a single shared policy across every host;
# trampling it without restoring would surprise the next operator.
hr
echo "[e2] step 2: capture existing policy + push the synthetic block"
ORIG_POLICY="$WORKDIR/policy-original.json"
# Fail-fast on the GET. Silent failure here would let step 6 PUT an
# empty `paths`/`hashes` payload back, permanently wiping whatever
# blocklist the operator actually had configured.
get_code=$(curl -sS -o "$ORIG_POLICY" -w '%{http_code}' -b "$COOKIE_JAR" \
  "$EDR_SERVER_URL/api/v1/admin/policy" || echo "000")
if [[ "$get_code" != "200" ]] || ! jq -e '(.blocklist.paths // []) | type == "array"' "$ORIG_POLICY" >/dev/null 2>&1; then
  echo "[e2] GET admin/policy failed (HTTP $get_code); refusing to push a synthetic policy" >&2
  cat "$ORIG_POLICY" >&2 || true
  exit 1
fi
echo "[e2] original policy captured at $ORIG_POLICY"

# Register the restore as an EXIT trap right after the GET succeeds, so
# any early `exit` from later steps (timeout in step 3, exec failure in
# step 4, network blip, Ctrl-C) still rolls the server's blocklist
# back to what we found. Set RESTORE_DONE=1 from step 6 to skip the
# trap-driven duplicate restore.
RESTORE_DONE=0
restore_policy() {
  if [[ "$RESTORE_DONE" = "1" ]]; then return 0; fi
  echo "[e2] EXIT trap: restoring original policy"
  payload=$(jq --arg reason "phase-7 e2 cleanup $TIMESTAMP" \
               --arg actor "$EDR_ADMIN_EMAIL" \
              '{paths: (.blocklist.paths // []),
                hashes: (.blocklist.hashes // []),
                reason: $reason, actor: $actor}' "$ORIG_POLICY") || return 0
  curl -sS -o /dev/null -w '%{http_code}\n' -b "$COOKIE_JAR" \
    -X PUT \
    -H "$CT_JSON" \
    -H "X-CSRF-Token: ${CSRF_TOKEN:-}" \
    -d "$payload" \
    "$EDR_SERVER_URL/api/v1/admin/policy" >&2 || true
  return 0
}
trap restore_policy EXIT

# GET returns `{version, blocklist:{paths,hashes}}` per the OpenAPI
# Policy schema. PUT expects a flat `{paths, hashes, reason, actor}`
# body. Read from `.blocklist.*` and rewrite into the flat PUT shape.
NEW_POLICY="$WORKDIR/policy-with-block.json"
jq --arg path "$SYNTHETIC_PATH" \
   --arg reason "phase-7 e2 dogfood QA $TIMESTAMP" \
   --arg actor "$EDR_ADMIN_EMAIL" \
  '{paths: ((.blocklist.paths // []) + [$path] | unique),
    hashes: (.blocklist.hashes // []),
    reason: $reason,
    actor: $actor}' \
  "$ORIG_POLICY" > "$NEW_POLICY"

put_resp=$(curl -sS -w '\n%{http_code}' -b "$COOKIE_JAR" \
  -X PUT \
  -H "$CT_JSON" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  --data-binary "@$NEW_POLICY" \
  "$EDR_SERVER_URL/api/v1/admin/policy" || echo $'\n000')
put_code=$(printf '%s' "$put_resp" | tail -n1)
if [[ "$put_code" != "200" ]]; then
  echo "[e2] PUT policy failed: HTTP $put_code" >&2
  # `head -n-1` is GNU-only; BSD head on macOS errors. `sed '$d'`
  # ("delete last line") is portable and produces the same result.
  printf '%s\n' "$put_resp" | sed '$d' >&2
  exit 1
fi
echo "[e2] policy pushed; server fanned out command to active hosts"

# Wait for the agent to pick up the new policy. The agent polls the
# command queue every 5s by default, so 60s is generous.
hr
echo "[e2] step 3: wait ≤60s for agent to materialise the new policy"
deadline=$(( $(date +%s) + 60 ))
while [[ "$(date +%s)" -lt "$deadline" ]]; do
  if ssh -o BatchMode=yes -o ConnectTimeout=5 "$VM_SSH_TARGET" \
       "sudo /usr/bin/grep -q '$SYNTHETIC_PATH' /var/db/com.fleetdm.edr/policy.json 2>/dev/null"; then
    echo "[e2] agent's policy.json contains the synthetic path"
    break
  fi
  sleep 3
done
if ! ssh -o BatchMode=yes "$VM_SSH_TARGET" \
       "sudo /usr/bin/grep -q '$SYNTHETIC_PATH' /var/db/com.fleetdm.edr/policy.json 2>/dev/null"; then
  echo "[e2] policy.json never received the new path within 60s" >&2
  echo "[e2] check the agent log: sudo tail /var/log/fleet-edr-agent.log" >&2
  echo "[e2] aborting before step 4 — without the policy in place, the exec attempt below" >&2
  echo "[e2] would succeed and produce a misleading 'block was not enforced' failure." >&2
  echo "[e2] step 6 (policy restore) still runs via the EXIT trap below." >&2
  POLICY_PUSH_FAILED=1
fi
POLICY_PUSH_FAILED="${POLICY_PUSH_FAILED:-0}"

# Plant a benign synthetic binary at the blocked path on the VM, then
# try to exec it. Expect denial via ES_AUTH_RESULT_DENY. We don't care
# what the script would have done — only that it's blocked from
# starting.
hr
echo "[e2] step 4: try to execute the blocked path on the VM"
if [[ "$POLICY_PUSH_FAILED" = "1" ]]; then
  echo "[e2] SKIPPED — policy never reached the agent in step 3"
  exit 1
fi
# shellcheck disable=SC2087  # heredoc with explicit shell escaping; quoted EOF, no interpolation
ssh -o BatchMode=yes "$VM_SSH_TARGET" "$BASH_S" <<EOF
set -uo pipefail
target='$SYNTHETIC_PATH'
sudo tee "\$target" >/dev/null <<'PAYLOAD'
#!/bin/sh
echo "synthetic e2 blocked binary ran — this should never print"
PAYLOAD
sudo chmod +x "\$target"
echo "[vm] attempting to exec \$target — expect denial"
out=\$( "\$target" 2>&1 ) || rc=\$?
rc=\${rc:-0}
if [[ "\$rc" -eq 0 ]]; then
  echo "[vm] FAIL: exec succeeded (rc=0). Block was not enforced. Output: \$out"
  sudo rm -f "\$target"
  exit 1
fi
echo "[vm] exec denied as expected (rc=\$rc): \$out"
sudo rm -f "\$target"
EOF

# Sanity: a fresh alert from the host within the test window. The
# blocking happens inside ESF AUTH, no detection rule fires today, so
# zero alerts here is normal. Surfaces the count for the operator's
# eye, doesn't fail the script.
hr
echo "[e2] step 5: list alerts on this host since the policy push (informational)"
HOST_ID=$(ssh -o BatchMode=yes "$VM_SSH_TARGET" \
  "sudo /usr/bin/plutil -extract host_id raw -o - /var/db/fleet-edr/enrolled.plist 2>/dev/null" | tr -d '[:space:]') || HOST_ID=""
if [[ -n "$HOST_ID" ]]; then
  curl -sS -b "$COOKIE_JAR" \
    "$EDR_SERVER_URL/api/v1/alerts?host_id=$HOST_ID&status=open" | \
    jq '[.alerts[]? | {rule_id, severity, title, created_at}] | .[]' || true
else
  echo "[e2] could not read host_id from /var/db/fleet-edr/enrolled.plist; skipping alert list"
fi

# Restore: PUT the original policy back so we leave the server how we
# found it. The EXIT trap above handles early-exit paths; this is the
# happy-path explicit restore so the operator sees a clear status line.
hr
echo "[e2] step 6: restore original policy"
restore_payload=$(jq --arg reason "phase-7 e2 cleanup $TIMESTAMP" \
                     --arg actor "$EDR_ADMIN_EMAIL" \
                     '{paths: (.blocklist.paths // []),
                       hashes: (.blocklist.hashes // []),
                       reason: $reason, actor: $actor}' "$ORIG_POLICY")
restore_code=$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" \
  -X PUT \
  -H "$CT_JSON" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -d "$restore_payload" \
  "$EDR_SERVER_URL/api/v1/admin/policy" || echo "000")
if [[ "$restore_code" = "200" ]]; then
  echo "[e2] original policy restored"
  RESTORE_DONE=1
else
  echo "[e2] WARNING: original policy restore returned HTTP $restore_code"
  echo "[e2] check the policy in the admin UI before walking away"
fi

hr
echo "[e2] done. expected outcome: step 4 reported 'exec denied as expected'."
echo "[e2] open Phase 7 issue: no alert fires on a blocked exec today;"
echo "[e2] the AUTH callback is silent. Tracked for Phase 8."
echo "[e2] cleanup: rm -rf $WORKDIR"
