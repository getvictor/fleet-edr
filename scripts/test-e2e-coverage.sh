#!/usr/bin/env bash
# Orchestrate the full E2E coverage pipeline. Builds an instrumented
# server binary once, then drives it through SEVERAL phases - each
# with its own env - restarting the binary between phases so the
# in-memory rate-limit buckets reset cleanly and each phase tests its
# specific env in isolation. All phases share GOCOVERDIR; the cover
# runtime writes per-process covcounters.<PID>.* files into one
# directory, and `go tool covdata textfmt` merges them into the
# single coverage-server-e2e.out report at the end.
#
# Phases (in order):
#   1. default-env-auth   : auth specs (break-glass setup, break-glass
#                           login, OIDC sign-in)
#   2. default-env-qa     : default-env qa specs (RBAC + reauth +
#                           audit + reauth-modal + break-glass login
#                           failure-reason)
#   3. default-env-rate-limit : break-glass challenge rate limit on
#                               default env. Burns the per-IP bucket,
#                               but a server restart between phases
#                               means subsequent phases start fresh
#   4. envspec-allowlist-jit-off : break-glass IP allowlist + OIDC
#                                  JIT-off in one server boot. Their
#                                  envs are orthogonal: allowlist
#                                  blocks /admin/break-glass/* and
#                                  JIT=0 rejects unknown OIDC
#                                  subjects, neither affects the other
#   5. short-session-timeouts : session lifecycle specs against tight
#                               idle windows so wall-clock waits are
#                               seconds, not minutes
#
# Tighter timeouts in CI than the recommended local defaults: the
# script sets idle=5s / break-glass-idle=3s so the two idle-eviction
# tests sit for 7s + 5s respectively rather than 18s + 11s. The spec
# reads E2E_OIDC_IDLE_WAIT_MS + E2E_BREAKGLASS_IDLE_WAIT_MS from env;
# defaults match the local-dev envs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# GitHub Actions log group markers.
readonly END_GROUP="::endgroup::"

COVDATA_DIR="$REPO_ROOT/tmp/covdata-e2e"
LOG_DIR="$REPO_ROOT/tmp/e2e-server-logs"
BINARY="$REPO_ROOT/tmp/edr-server-e2e"
COV_OUT="$REPO_ROOT/coverage-server-e2e.out"

# Common server env. Phases append/override; see start_server.
# TLS is mandatory (issue #140): generate the dev cert pair before phases run.
# The covered binary refuses to boot without EDR_TLS_CERT_FILE + EDR_TLS_KEY_FILE.
task dev:certs > /dev/null
COMMON_ENV=(
  EDR_DSN="root:@tcp(127.0.0.1:33306)/edr?parseTime=true"
  EDR_ENROLL_SECRET=dev-enroll-secret
  EDR_TLS_CERT_FILE="$REPO_ROOT/tmp/dev.crt"
  EDR_TLS_KEY_FILE="$REPO_ROOT/tmp/dev.key"
  EDR_LISTEN_ADDR="0.0.0.0:8088"
  EDR_LOG_FORMAT=text
  EDR_HOST_TOKEN_LIFETIME=24h
  EDR_HOST_TOKEN_GRACE=5m
  # Raise the per-IP enroll cap well above the suite's enroll volume. Every spec enrolls its hosts from the one CI runner IP,
  # so the production default (30/min, burst 30) is occasionally exhausted mid-suite and a setup enroll gets a 429, flaking
  # an unrelated test. No E2E spec asserts the enroll limiter (the rate-limit specs cover break-glass, a separate limiter), so
  # raising it here removes the flake without weakening coverage.
  EDR_ENROLL_RATE_PER_MIN=100000
  EDR_SECRET_KEY=dev-only-secret-key-do-not-use-in-production-xyz
  EDR_BREAKGLASS_RP_ID=localhost
  EDR_BREAKGLASS_RP_ORIGINS=https://localhost:8088
  EDR_OIDC_ISSUER=http://localhost:5556/dex
  EDR_OIDC_CLIENT_ID=edr-qa
  EDR_OIDC_CLIENT_SECRET=edr-qa-client-secret-do-not-use-in-prod
  EDR_OIDC_REDIRECT_URL=https://localhost:8088/api/auth/callback
  GOCOVERDIR="$COVDATA_DIR"
)

# Drain any lingering server, wait for :8088 to free, then idle.
SERVER_PID=""
stop_server() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    # Give the cover runtime up to 10s to flush covcounters.* files.
    for _ in $(seq 1 10); do
      if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        break
      fi
      sleep 1
    done
    if kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "  server didn't honour SIGTERM; SIGKILL"
      kill -KILL "$SERVER_PID" 2>/dev/null || true
    fi
  fi
  # Wait for the port to fully release so the next start doesn't
  # EADDRINUSE. Probe via /readyz instead of lsof: lsof isn't
  # guaranteed in minimal CI images, and a 200 reply from /readyz
  # specifically means there's still a working server on the port,
  # which is what we'd care about either way.
  for _ in $(seq 1 10); do
    if ! curl -fsSk https://localhost:8088/readyz > /dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  SERVER_PID=""
}

# start_server <phase-name> <KEY=VAL> ...
# Spawns the covered binary in the background with COMMON_ENV plus any
# phase-specific overrides, captures the PID, and waits for /readyz.
start_server() {
  local phase="$1"
  shift
  local log="$LOG_DIR/${phase}.log"

  # Combine common + phase env. Phase env wins for any overlapping key
  # because bash's later `env` arg overrides earlier ones.
  env "${COMMON_ENV[@]}" "$@" "$BINARY" > "$log" 2>&1 &
  SERVER_PID=$!
  echo "  phase=$phase pid=$SERVER_PID env_overrides=$*"

  for i in $(seq 1 30); do
    # Fail fast if the server PID exited before /readyz answered -
    # otherwise a 8088 hand-off to a foreign process would silently
    # invalidate the coverage profile (no covcounters file from this
    # PID) and pass the readiness check against the wrong server.
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "::error::server PID $SERVER_PID died during boot for phase=$phase" >&2
      cat "$log" >&2
      SERVER_PID=""
      exit 1
    fi
    if curl -fsSk https://localhost:8088/readyz > /dev/null 2>&1; then
      echo "  ready after ${i}s"
      return 0
    fi
    sleep 1
  done
  echo "::error::server failed to boot for phase=$phase" >&2
  cat "$log" >&2
  stop_server
  exit 1
}

# Always drain on exit, even on a thrown error.
trap stop_server EXIT

# --- prep -----------------------------------------------------------------
rm -rf "$COVDATA_DIR" "$LOG_DIR" "$COV_OUT" "$REPO_ROOT/test/e2e/coverage-raw" "$REPO_ROOT/test/e2e/coverage"
mkdir -p "$COVDATA_DIR" "$LOG_DIR"

echo "::group::Build covered server binary"
go build -cover -coverpkg=./server/...,./internal/... -o "$BINARY" ./server/cmd/fleet-edr-server
echo "$END_GROUP"

# --- phase 1: auth suite (default env) -----------------------------------
echo "::group::Phase 1 - auth specs (break-glass setup, break-glass login, OIDC sign-in)"
start_server "default-env-auth" \
  EDR_OIDC_ALLOW_JIT_PROVISIONING=1
(
  cd "$REPO_ROOT/test/e2e"
  E2E_REUSE_SERVER=1 E2E_COVERAGE=1 ./node_modules/.bin/playwright test tests/auth
)
stop_server
echo "$END_GROUP"

# --- phase 2: qa default-env suite ---------------------------------------
# Includes the M5 wire smoke (agent-events-flow.spec.ts) and M6 UI specs (host-list-and-process-tree.spec.ts) - both consume the
# break-glass setup endpoint, so they share this phase's 5/min token budget with reauth-modal-retry. The set is intentionally short
# enough that the bucket doesn't overflow within the phase.
echo "::group::Phase 2 - qa default-env (RBAC, reauth, audit, reauth-modal, break-glass login failures, agent wire + UI)"
start_server "default-env-qa" \
  EDR_OIDC_ALLOW_JIT_PROVISIONING=1
(
  cd "$REPO_ROOT/test/e2e"
  E2E_REUSE_SERVER=1 E2E_COVERAGE=1 ./node_modules/.bin/playwright test \
    tests/qa/authz-and-audit-flows.spec.ts \
    tests/qa/breakglass-login-failure-reason.spec.ts \
    tests/qa/reauth-modal-retry.spec.ts \
    tests/qa/agent-events-flow.spec.ts \
    tests/qa/host-list-and-process-tree.spec.ts \
    --workers=1
)
stop_server
echo "$END_GROUP"

# --- phase 3: brute-force rate limit -------------------------------------
echo "::group::Phase 3 - break-glass challenge rate limit (default env)"
start_server "default-env-rate-limit" \
  EDR_OIDC_ALLOW_JIT_PROVISIONING=1
(
  cd "$REPO_ROOT/test/e2e"
  E2E_REUSE_SERVER=1 E2E_COVERAGE=1 ./node_modules/.bin/playwright test \
    tests/qa/breakglass-challenge-rate-limit.spec.ts --workers=1
)
stop_server
echo "$END_GROUP"

# --- phase 4: env-specific combo (allowlist + JIT off) -------------------
echo "::group::Phase 4 - break-glass IP allowlist + OIDC JIT off"
start_server "envspec-allowlist-jit-off" \
  EDR_BREAKGLASS_IP_ALLOWLIST=10.99.99.0/24 \
  EDR_OIDC_ALLOW_JIT_PROVISIONING=0
(
  cd "$REPO_ROOT/test/e2e"
  E2E_REUSE_SERVER=1 E2E_COVERAGE=1 ./node_modules/.bin/playwright test \
    tests/qa/breakglass-ip-allowlist.spec.ts \
    tests/qa/oidc-jit-disabled.spec.ts \
    --workers=1
)
stop_server
echo "$END_GROUP"

# --- phase 5: short session timeouts -------------------------------------
echo "::group::Phase 5 - session lifecycle (short timeouts env)"
start_server "short-session-timeouts" \
  EDR_OIDC_ALLOW_JIT_PROVISIONING=1 \
  EDR_SESSION_IDLE_TIMEOUT=5s \
  EDR_SESSION_ABSOLUTE_TIMEOUT=20s \
  EDR_BREAKGLASS_SESSION_IDLE_TIMEOUT=3s \
  EDR_BREAKGLASS_SESSION_ABSOLUTE_TIMEOUT=10s
(
  cd "$REPO_ROOT/test/e2e"
  # Match the server-side idle windows: sleep 7s past OIDC idle (5s
  # → 7s), 5s past break-glass idle (3s → 5s). The spec defaults to
  # 18s/11s for the local-dev env (idle=15s/8s); the env var overrides
  # drop CI wall clock by ~17s.
  E2E_REUSE_SERVER=1 E2E_COVERAGE=1 \
    E2E_OIDC_IDLE_WAIT_MS=7000 \
    E2E_BREAKGLASS_IDLE_WAIT_MS=5000 \
    ./node_modules/.bin/playwright test tests/qa/session-lifecycle.spec.ts --workers=1
)
stop_server
echo "$END_GROUP"

trap - EXIT  # cleanup already ran via the final stop_server

# --- merge Go coverage ---------------------------------------------------
echo "::group::Merge Go coverage → coverage-server-e2e.out"
echo "covdata files:"
ls -la "$COVDATA_DIR" | head -20
go tool covdata textfmt -i="$COVDATA_DIR" -o="$COV_OUT"
echo "wrote $COV_OUT ($(wc -l < "$COV_OUT") lines)"
echo "$END_GROUP"

# --- convert UI V8 coverage ---------------------------------------------
echo "::group::Convert UI V8 coverage → lcov-e2e.info"
(
  cd "$REPO_ROOT/test/e2e"
  node scripts/coverage-to-lcov.mjs
)
echo "$END_GROUP"
