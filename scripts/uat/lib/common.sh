# scripts/uat/lib/common.sh -- shared helpers for the L5 system-test driver.
#
# Sourced (not executed) by scripts/uat/system-test.sh and by scenario attack.sh
# files when they need server REST access. Defines uat_* functions; sets
# UAT_COOKIE_JAR + UAT_CSRF_TOKEN globals after a successful uat_server_login.
#
# Conventions:
#   - All functions return non-zero on failure and print diagnostics to stderr.
#   - HTTP helpers use --fail-with-body so non-2xx surfaces as a clear error
#     rather than silently writing an empty body.
#   - SSH helpers use BatchMode=yes so a missing key fails fast instead of
#     hanging on a password prompt.
#   - No `set -e` here -- scripts that source us choose their own strictness
#     (the driver uses `set -uEo pipefail` minus -e so partial failures don't
#     mask later steps).

# Guard against double-sourcing: the driver may source us once and a scenario
# attack.sh may source us again. Without the guard, redefining functions on
# the second source is benign but redeclaring readonly UAT_* constants would
# trip set -u via "readonly variable" errors.
if [[ -n "${UAT_COMMON_SH_LOADED:-}" ]]; then
  return 0
fi
UAT_COMMON_SH_LOADED=1

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

# uat_log <tag> <msg...>: timestamped structured stderr line.
# Tag is the active scenario id or "driver"; the timestamp lets the operator
# correlate the script's view with `log show --predicate ...` on the VM.
uat_log() {
  local tag="$1"; shift
  printf '[%s] [%s] %s\n' "$(date '+%H:%M:%S')" "$tag" "$*" >&2
}

# uat_fail <tag> <msg...>: log then exit 1.
uat_fail() {
  uat_log "$1" "FAIL: ${*:2}"
  exit 1
}

# ---------------------------------------------------------------------------
# SSH wrappers
# ---------------------------------------------------------------------------

# uat_ssh_args: build the ssh option flags we use everywhere. BatchMode=yes
# fails fast on missing keys (no password prompt); StrictHostKeyChecking
# accept-new auto-trusts edr-qa's host key on first connect but refuses if
# the key later changes. UserKnownHostsFile uses a per-run file so a VM
# rebuild + ssh fingerprint change doesn't trip the host-key warning.
uat_ssh_args() {
  printf -- '-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s -o ConnectTimeout=10' \
    "${UAT_KNOWN_HOSTS:-$HOME/.ssh/known_hosts_edr_uat}"
}

# uat_ssh <target> <cmd...>: run cmd over ssh on target. Honors $UAT_DRY_RUN.
# Args are joined into a single remote command string, which ssh runs through
# the remote login shell. Callers pass already-quoted command strings (or
# argv elements safe to expand) -- we deliberately don't shell-escape here
# because every callsite is in this repo and reviewed; doing the escape would
# break the common pattern `uat_ssh "$vm" 'sudo systemextensionsctl list'`.
uat_ssh() {
  local target="$1"; shift
  if [[ "${UAT_DRY_RUN:-0}" == "1" ]]; then
    uat_log driver "DRY-RUN ssh $target -- $*"
    return 0
  fi
  # SC2046: word-split of uat_ssh_args is intentional (it returns a string of flags).
  # SC2029: client-side expansion is the desired remote-cmd-string semantic.
  # shellcheck disable=SC2046,SC2029
  ssh $(uat_ssh_args) "$target" "$@"
}

# uat_scp <src> <target>:<dst>: copy a file onto the VM.
uat_scp() {
  local src="$1" target_path="$2"
  if [[ "${UAT_DRY_RUN:-0}" == "1" ]]; then
    uat_log driver "DRY-RUN scp $src -> $target_path"
    return 0
  fi
  # shellcheck disable=SC2046
  scp $(uat_ssh_args) "$src" "$target_path"
}

# ---------------------------------------------------------------------------
# Server REST helpers
# ---------------------------------------------------------------------------

# uat_server_login: POST /api/v1/session with EDR_ADMIN_EMAIL / EDR_ADMIN_PASSWORD,
# stash the session cookie in UAT_COOKIE_JAR, expose csrf_token as UAT_CSRF_TOKEN.
# Idempotent: a second login overwrites with a fresh session.
uat_server_login() {
  # Dry-run short-circuit MUST come before the env-required checks: a
  # contributor invoking `--dry-run` for the first time on a fresh checkout
  # has none of these envs set and shouldn't be forced to fake them.
  if [[ "${UAT_DRY_RUN:-0}" == "1" ]]; then
    UAT_COOKIE_JAR="${UAT_TMPDIR:-/tmp}/uat-cookies"
    UAT_CSRF_TOKEN="dry-run-csrf-token"
    uat_log driver "DRY-RUN login -> ${EDR_SERVER_URL:-<unset>}"
    return 0
  fi
  : "${EDR_SERVER_URL:?missing required env}"
  : "${EDR_ADMIN_EMAIL:?missing required env}"
  : "${EDR_ADMIN_PASSWORD:?missing required env}"
  UAT_COOKIE_JAR="${UAT_TMPDIR:-$(mktemp -d)}/cookies"
  local body
  body="${UAT_TMPDIR:-/tmp}/login-body"
  local http_code
  http_code=$(curl -sS --fail-with-body \
    -o "$body" -w '%{http_code}' \
    -c "$UAT_COOKIE_JAR" \
    -H 'Content-Type: application/json' \
    -d "$(printf '{"email":%s,"password":%s}' \
          "$(printf '%s' "$EDR_ADMIN_EMAIL" | jq -R .)" \
          "$(printf '%s' "$EDR_ADMIN_PASSWORD" | jq -R .)")" \
    "$EDR_SERVER_URL/api/v1/session" 2>/dev/null) || http_code=000
  if [[ "$http_code" != "200" ]]; then
    uat_log driver "login failed: HTTP $http_code; response body:"
    [[ -f "$body" ]] && cat "$body" >&2
    return 1
  fi
  UAT_CSRF_TOKEN=$(jq -r '.csrf_token // ""' "$body")
  if [[ -z "$UAT_CSRF_TOKEN" || "$UAT_CSRF_TOKEN" == "null" ]]; then
    uat_log driver "login response missing csrf_token"
    return 1
  fi
}

# uat_server_get <path> <out_file>: GET <EDR_SERVER_URL><path> with the
# session cookie. Returns 0 on 2xx, 1 otherwise; out_file always contains the
# response body so the caller can inspect on failure.
uat_server_get() {
  local path="$1" out="$2"
  if [[ "${UAT_DRY_RUN:-0}" == "1" ]]; then
    echo '{"alerts":[]}' > "$out"
    uat_log driver "DRY-RUN GET $path -> empty alerts list"
    return 0
  fi
  local http_code
  http_code=$(curl -sS --fail-with-body \
    -o "$out" -w '%{http_code}' \
    -b "$UAT_COOKIE_JAR" \
    "$EDR_SERVER_URL$path" 2>/dev/null) || http_code=000
  [[ "$http_code" =~ ^2 ]]
}

# ---------------------------------------------------------------------------
# Alert polling
# ---------------------------------------------------------------------------

# uat_poll_alerts <host_id> <rule_id> <within_seconds>: poll the server's
# alerts endpoint for an alert matching the (host_id, rule_id) pair. Returns
# 0 on first match, 1 if the deadline expires.
#
# The endpoint is `/api/v1/alerts?host_id=<id>&rule_id=<rid>&since=<window>`;
# `since` is set to `started_at - 30s` so a slightly-clock-skewed VM doesn't
# miss alerts emitted in the moments before the polling window begins.
uat_poll_alerts() {
  local host_id="$1" rule_id="$2" within="$3"
  # Dry-run short-circuit: log what we WOULD poll for and return success.
  # The driver's smoke-test contract is "--dry-run never fails", and a fake
  # poll-miss would otherwise diverge from that. Operators see the GET line
  # via uat_server_get's own DRY-RUN log message immediately above this.
  if [[ "${UAT_DRY_RUN:-0}" == "1" ]]; then
    local body
    body="${UAT_TMPDIR:-/tmp}/alerts-$rule_id.json"
    uat_server_get "/api/v1/alerts?host_id=$host_id&rule_id=$rule_id&limit=10" "$body" >/dev/null
    return 0
  fi
  local deadline
  deadline=$(( $(date +%s) + within ))
  local body
  body="${UAT_TMPDIR:-/tmp}/alerts-$rule_id.json"
  while (( $(date +%s) < deadline )); do
    if uat_server_get \
        "/api/v1/alerts?host_id=$host_id&rule_id=$rule_id&limit=10" \
        "$body" \
       && [[ "$(jq -r '.alerts | length' "$body" 2>/dev/null)" -gt 0 ]]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# ---------------------------------------------------------------------------
# Extension activation polling
# ---------------------------------------------------------------------------

# uat_wait_for_extension <vm_target> <within_seconds>: SSH into the VM and
# poll `systemextensionsctl list` until the EDR extension shows up as
# `[activated enabled]`. Catches signing / notarization regressions in the
# PKG: an unsigned PKG installs but the extension never activates.
uat_wait_for_extension() {
  local vm="$1" within="$2"
  local deadline
  deadline=$(( $(date +%s) + within ))
  while (( $(date +%s) < deadline )); do
    if uat_ssh "$vm" "systemextensionsctl list | grep -q 'com.fleetdm.edr.*activated enabled'" \
        >/dev/null 2>&1; then
      return 0
    fi
    if [[ "${UAT_DRY_RUN:-0}" == "1" ]]; then
      return 0
    fi
    sleep 5
  done
  return 1
}

# uat_wait_for_host_enrolment <hostname> <within_seconds>: poll the server's
# /api/v1/hosts list until a host with the matching hostname (or hardware
# UUID) appears. The driver uses this after PKG install to make sure the
# agent actually enrolled rather than silently failing on a bad
# enroll_secret. Returns the host's UUID on success via stdout.
uat_wait_for_host_enrolment() {
  local hostname="$1" within="$2"
  local deadline
  deadline=$(( $(date +%s) + within ))
  local body
  body="${UAT_TMPDIR:-/tmp}/hosts.json"
  while (( $(date +%s) < deadline )); do
    if uat_server_get "/api/v1/hosts?limit=100" "$body"; then
      local host_id
      host_id=$(jq -r --arg h "$hostname" \
        '.hosts[]? | select(.hostname == $h) | .host_id' \
        "$body" 2>/dev/null | head -1)
      if [[ -n "$host_id" && "$host_id" != "null" ]]; then
        echo "$host_id"
        return 0
      fi
    fi
    if [[ "${UAT_DRY_RUN:-0}" == "1" ]]; then
      echo "00000000-0000-0000-0000-DRYRUNDRYRUN"
      return 0
    fi
    sleep 5
  done
  return 1
}
