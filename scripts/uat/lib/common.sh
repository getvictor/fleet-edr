# scripts/uat/lib/common.sh -- shared helpers for the L5 system-test driver.
#
# Sourced (not executed) by scripts/uat/system-test.sh and by scenario attack.sh
# files when they need server REST access. Defines uat_* functions; sets
# UAT_COOKIE_HEADER + UAT_CSRF_TOKEN globals after a successful uat_server_warmup.
#
# Conventions:
#   - All functions return non-zero on failure and print diagnostics to stderr.
#   - HTTP helpers use --fail-with-body so non-2xx surfaces as a clear error
#     rather than silently writing an empty body. curl's stderr is NOT redirected:
#     a TLS handshake failure / DNS error / connection refused is exactly the
#     diagnostic an operator needs when a scenario falls over before reaching
#     the application layer.
#   - SSH helpers use BatchMode=yes so a missing key fails fast instead of
#     hanging on a password prompt.
#   - `set -e` is enabled at the script level (driver + scenario wrappers); this
#     library is sourced into that strict mode. Functions that internally
#     tolerate a failing curl handle it explicitly via `|| http_code=000` so
#     the conditional context suppresses errexit for those branches.

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

# uat_ssh_args: populate the UAT_SSH_ARGS array with the ssh option flags we
# use everywhere. An ARRAY is used (not a string) so callers can expand
# `"${UAT_SSH_ARGS[@]}"` with proper quoting -- the previous string-returning
# shape forced unquoted `ssh $(uat_ssh_args)` word-splitting, which broke if
# UAT_KNOWN_HOSTS contained whitespace.
#
# BatchMode=yes fails fast on missing keys (no password prompt);
# StrictHostKeyChecking accept-new auto-trusts edr-qa's host key on first
# connect but refuses if the key later changes. UserKnownHostsFile uses a
# per-run file so a VM rebuild + ssh fingerprint change doesn't trip the
# host-key warning.
uat_ssh_args() {
  local known_hosts="${UAT_KNOWN_HOSTS:-$HOME/.ssh/known_hosts_edr_uat}"
  UAT_SSH_ARGS=(
    -o BatchMode=yes
    -o StrictHostKeyChecking=accept-new
    -o "UserKnownHostsFile=$known_hosts"
    -o ConnectTimeout=10
  )
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
  uat_ssh_args
  # SC2029: client-side expansion of "$@" is the desired remote-cmd-string
  # semantic; we want the command to be assembled here and shipped to ssh.
  # shellcheck disable=SC2029
  ssh "${UAT_SSH_ARGS[@]}" "$target" "$@"
}

# uat_scp <src> <target>:<dst>: copy a file onto the VM.
uat_scp() {
  local src="$1" target_path="$2"
  if [[ "${UAT_DRY_RUN:-0}" == "1" ]]; then
    uat_log driver "DRY-RUN scp $src -> $target_path"
    return 0
  fi
  uat_ssh_args
  scp "${UAT_SSH_ARGS[@]}" "$src" "$target_path"
}

# ---------------------------------------------------------------------------
# Server REST helpers
# ---------------------------------------------------------------------------

# uat_server_warmup: validate that the user-provided EDR_SESSION_COOKIE actually
# works against the live server, and fetch the per-session CSRF token from the
# GET /api/session endpoint for any subsequent state-changing requests. Stores
# the cookie header in UAT_COOKIE_HEADER (an array) and the CSRF token in
# UAT_CSRF_TOKEN. Idempotent: a second call overwrites both.
#
# Why a pre-minted cookie rather than POST /api/session login: the server has
# NO password-based POST /api/session route -- login is OIDC (browser redirect
# to dex/IdP) or break-glass WebAuthn ceremony (passkey, browser-only). Neither
# is shell-scriptable. The realistic L5 flow is: operator does ONE browser
# login, copies the `edr_session` cookie from devtools, exports it as
# EDR_SESSION_COOKIE, and reuses it across many scenario runs until the
# session expires.
uat_server_warmup() {
  # Dry-run short-circuit MUST come before the env-required checks: a
  # contributor invoking `--dry-run` for the first time on a fresh checkout
  # has none of these envs set and shouldn't be forced to fake them.
  if [[ "${UAT_DRY_RUN:-0}" == "1" ]]; then
    UAT_COOKIE_HEADER=(-H "Cookie: edr_session=dry-run")
    UAT_CSRF_TOKEN="dry-run-csrf-token"
    uat_log driver "DRY-RUN session warmup -> ${EDR_SERVER_URL:-<unset>}"
    return 0
  fi
  # Explicit checks rather than `${VAR:?msg}` so callers under `set -e` + EXIT
  # trap see a clean exit code -- bash's `:?` resets $? to 0 at trap entry.
  if [[ -z "${EDR_SERVER_URL:-}" ]]; then
    uat_log driver "missing required env EDR_SERVER_URL"
    return 1
  fi
  if [[ -z "${EDR_SESSION_COOKIE:-}" ]]; then
    uat_log driver "missing required env EDR_SESSION_COOKIE -- see scripts/uat/README.md \"Auth flow\""
    return 1
  fi

  UAT_COOKIE_HEADER=(-H "Cookie: edr_session=$EDR_SESSION_COOKIE")

  # GET /api/session is session-protected; a successful response confirms the
  # cookie is valid AND returns the CSRF token in the body. A 401 here means
  # the cookie expired -- the operator does another browser login and updates
  # EDR_SESSION_COOKIE.
  local body
  body="${UAT_TMPDIR:-/tmp}/session-body"
  local http_code
  http_code=$(curl -sS --fail-with-body \
    -o "$body" -w '%{http_code}' \
    "${UAT_COOKIE_HEADER[@]}" \
    "$EDR_SERVER_URL/api/session") || http_code=000
  if [[ "$http_code" != "200" ]]; then
    uat_log driver "GET /api/session failed: HTTP $http_code (EDR_SESSION_COOKIE expired or invalid?)"
    [[ -f "$body" ]] && cat "$body" >&2
    return 1
  fi
  UAT_CSRF_TOKEN=$(jq -r '.csrf_token // ""' "$body")
  if [[ -z "$UAT_CSRF_TOKEN" || "$UAT_CSRF_TOKEN" == "null" ]]; then
    uat_log driver "GET /api/session response missing csrf_token"
    return 1
  fi
}

# uat_server_get <path> <out_file>: GET <EDR_SERVER_URL><path> with the
# session cookie header. Returns 0 on 2xx, 1 otherwise; out_file always
# contains the response body so the caller can inspect on failure.
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
    "${UAT_COOKIE_HEADER[@]}" \
    "$EDR_SERVER_URL$path") || http_code=000
  [[ "$http_code" =~ ^2 ]]
}

# ---------------------------------------------------------------------------
# Alert polling
# ---------------------------------------------------------------------------

# uat_poll_alerts <host_id> <rule_id> <within_seconds> <since_unix>: poll the
# server's /api/alerts endpoint for an alert matching the (host_id, rule_id)
# pair created at-or-after since_unix. Returns 0 on first match, 1 if the
# deadline expires.
#
# The endpoint is /api/alerts -- no `since` query parameter exists on the
# server, so we filter client-side via jq on `created_at >= since_unix`. The
# since gate guards against false positives from alerts emitted on the same
# host_id by a previous scenario run.
uat_poll_alerts() {
  local host_id="$1" rule_id="$2" within="$3" since_unix="$4"
  # Dry-run short-circuit: log what we WOULD poll for and return success.
  # The driver's smoke-test contract is "--dry-run never fails", and a fake
  # poll-miss would otherwise diverge from that. Operators see the GET line
  # via uat_server_get's own DRY-RUN log message immediately above this.
  if [[ "${UAT_DRY_RUN:-0}" == "1" ]]; then
    local body
    body="${UAT_TMPDIR:-/tmp}/alerts-$rule_id.json"
    uat_server_get "/api/alerts?host_id=$host_id&rule_id=$rule_id&limit=50" "$body" >/dev/null
    return 0
  fi
  local deadline
  deadline=$(( $(date +%s) + within ))
  local body
  body="${UAT_TMPDIR:-/tmp}/alerts-$rule_id.json"
  while (( $(date +%s) < deadline )); do
    if uat_server_get "/api/alerts?host_id=$host_id&rule_id=$rule_id&limit=50" "$body"; then
      local fresh_count
      fresh_count=$(jq -r --arg since "$since_unix" \
        '[.alerts[]? | select((.created_at_unix // 0) >= ($since | tonumber))] | length' \
        "$body" 2>/dev/null || echo 0)
      if [[ "$fresh_count" -gt 0 ]]; then
        return 0
      fi
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
    if uat_ssh "$vm" "systemextensionsctl list | grep -q 'com.fleetdm.edr.*activated enabled'"; then
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
# /api/hosts list until a host with the matching hostname (or hardware
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
    if uat_server_get "/api/hosts?limit=100" "$body"; then
      local host_id
      host_id=$(jq -r --arg h "$hostname" \
        '.hosts[]? | select(.hostname == $h) | .host_id' \
        "$body" | head -1)
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
