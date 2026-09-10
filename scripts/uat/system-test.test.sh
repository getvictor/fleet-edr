#!/usr/bin/env bash
#
# scripts/uat/system-test.test.sh
#
# Tests for the L5 driver's rule classification and the runbook's skip
# propagation (issues #965, #966). Runs with no VM and no server: the driver's
# --dry-run mode loads the scenario and short-circuits every remote call, which
# is enough to exercise the part that decides pass / miss / skipped.
#
# The receipt helper is covered here too, against a stubbed uat_ssh. It decides
# whether a failed installer command counts as a successful install, so leaving
# it to manual VM verification would leave the release gate's most consequential
# branch unguarded between runs.
#
# Still not covered: the installer invocation itself, which needs a real VM.
#
# Run: bash scripts/uat/system-test.test.sh   (or `task test:uat:driver`)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091  # path computed at runtime
. "$SCRIPT_DIR/lib/common.sh"

TESTS_RUN=0
TESTS_FAILED=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

check() {
  local name="$1" want="$2" got="$3"
  TESTS_RUN=$(( TESTS_RUN + 1 ))
  if [[ "$want" == "$got" ]]; then
    echo "  ok   $name"
  else
    echo "  FAIL $name"
    echo "         want: $want"
    echo "         got:  $got"
    TESTS_FAILED=$(( TESTS_FAILED + 1 ))
  fi
}

echo "uat_skip_reason"

# The ordinary case: the runbook could not run a step and said which prerequisite was missing.
UAT_SKIP_FILE="$TMP/skips.txt"
export UAT_SKIP_FILE
cat > "$UAT_SKIP_FILE" <<'EOF'
[runbook] SKIP rule_id=privilege_launchd_plist_write reason=no NOPASSWD sudo for the dropper
EOF
check "reports the prerequisite for a skipped rule" \
  "no NOPASSWD sudo for the dropper" "$(uat_skip_reason privilege_launchd_plist_write)"

# A rule that ran has no entry, and its silence later is a real detection miss rather than a skip.
check "reports nothing for a rule that ran" "" "$(uat_skip_reason suspicious_exec)"

# The reason runs to the end of the line: a prerequisite worth naming usually has spaces in it, and an early cut would
# report half of it.
cat > "$UAT_SKIP_FILE" <<'EOF'
[runbook] SKIP rule_id=suspicious_exec reason=no python3 on this host
EOF
check "keeps a multi-word reason whole" "no python3 on this host" "$(uat_skip_reason suspicious_exec)"

# Prefix collision. `suspicious_exec` is a prefix of `suspicious_exec_network`, and an unanchored match would hand the
# shorter rule the longer one's skip, silently excusing a rule that really did run and really did miss.
cat > "$UAT_SKIP_FILE" <<'EOF'
[runbook] SKIP rule_id=suspicious_exec_network reason=no network on this host
EOF
check "does not match a rule whose id is a prefix of another's" "" "$(uat_skip_reason suspicious_exec)"
check "still matches the rule that was actually skipped" \
  "no network on this host" "$(uat_skip_reason suspicious_exec_network)"

# No file at all is the normal state for a scenario whose attack.sh records no skips.
UAT_SKIP_FILE="$TMP/does-not-exist.txt"
check "treats a missing skip file as nothing skipped" "" "$(uat_skip_reason suspicious_exec)"

echo
echo "driver verdicts (--dry-run)"

run_driver() {
  local out
  out="$TMP/driver.log"
  ( cd "$SCRIPT_DIR/.." && ./uat/system-test.sh attack-runbook --dry-run ) > "$out" 2>&1
  DRIVER_EXIT=$?
  DRIVER_OUT="$(cat "$out")"
}

# The smoke-test contract the dry-run mode exists for: with nothing skipped it passes. Asserted here so the skip work
# cannot regress it, since a driver that fails its own smoke test is one nobody will run.
unset UAT_SKIP_FILE
run_driver
check "passes when every rule was exercised" "0" "$DRIVER_EXIT"
check "reports no skips" "1" "$(grep -c 'rules_skipped=0' <<<"$DRIVER_OUT")"

# A skipped rule takes exit 3, not 2 and not 0. Not 0 because a rule that never ran has not been certified and this is a
# release gate; not 2 because that is what a real detection miss means and conflating them is issue #965.
UAT_SKIP_FILE="$TMP/driver-skips.txt"
export UAT_SKIP_FILE
cat > "$UAT_SKIP_FILE" <<'EOF'
[runbook] SKIP rule_id=privilege_launchd_plist_write reason=no NOPASSWD sudo for the dropper
EOF
run_driver
check "exits 3 when a rule was never exercised" "3" "$DRIVER_EXIT"
check "verdict is INCOMPLETE, not FAIL" "1" "$(grep -c 'INCOMPLETE scenario=attack-runbook' <<<"$DRIVER_OUT")"
# Named in BOTH places on purpose: inline where the rule is classified, and again in the closing summary, so an operator
# reading only the tail of a long run still sees what to fix rather than having to scroll back for it.
check "names the prerequisite inline" "1" \
  "$(grep -c 'skipped: privilege_launchd_plist_write (prerequisite: no NOPASSWD sudo for the dropper)' <<<"$DRIVER_OUT")"
check "names the prerequisite again in the summary" "1" \
  "$(grep -c 'never exercised: privilege_launchd_plist_write (prerequisite: no NOPASSWD sudo for the dropper)' <<<"$DRIVER_OUT")"
# The misreport this whole change exists to remove: the skipped rule must not be reported as a detection miss.
check "does not report the skipped rule as a miss" "0" \
  "$(grep -c 'miss: privilege_launchd_plist_write' <<<"$DRIVER_OUT")"
check "counts the skip" "1" "$(grep -c 'rules_skipped=1' <<<"$DRIVER_OUT")"
# And the rules that DID run are still asserted rather than abandoned once one rule is skipped.
check "still checks the other five rules" "1" "$(grep -c 'rules_passed=5' <<<"$DRIVER_OUT")"

echo
echo "uat_wait_for_pkg_receipt"

# sleep is stubbed to a no-op so the negative cases, which must run to their deadline, do not each cost five seconds.
# Test-local: the helper keeps its real pacing in production.
# shellcheck disable=SC2329  # invoked indirectly: the helper under test calls `sleep`, which this shadows
sleep() { :; }

# uat_ssh is stubbed rather than reaching a VM. RECEIPT_OUT is what pkgutil would print through the helper's awk, so
# "" stands for a package with no receipt at all, which is what an install that never landed looks like.
RECEIPT_OUT=""
# Recorded to a FILE, not a variable: the helper calls uat_ssh inside a command substitution, which is a subshell, so an
# assignment here would never reach the assertion below.
RECEIPT_SAW="$TMP/receipt-cmd.txt"
# shellcheck disable=SC2329  # invoked indirectly: the helper under test calls `uat_ssh`, which this shadows
uat_ssh() { printf '%s' "$*" > "$RECEIPT_SAW"; printf '%s' "$RECEIPT_OUT"; }

RECEIPT_OUT="2000"
uat_wait_for_pkg_receipt vm com.fleetdm.edr.agent 1000 1 && got=0 || got=1
check "accepts a receipt newer than the mark" "0" "$got"

# Equal counts as fresh: an install that lands in the same second as the mark did happen, and rejecting it would make
# the gate flaky on a fast install rather than catching anything.
RECEIPT_OUT="1000"
uat_wait_for_pkg_receipt vm com.fleetdm.edr.agent 1000 1 && got=0 || got=1
check "accepts a receipt exactly at the mark" "0" "$got"

# The case the whole check exists for: the previous install's receipt must not certify this one.
RECEIPT_OUT="999"
uat_wait_for_pkg_receipt vm com.fleetdm.edr.agent 1000 1 && got=0 || got=1
check "rejects the receipt left by an earlier install" "1" "$got"

# No receipt at all: the package was never installed, which must not read as success.
RECEIPT_OUT=""
uat_wait_for_pkg_receipt vm com.fleetdm.edr.agent 1000 1 && got=0 || got=1
check "rejects an absent receipt" "1" "$got"

# Anything non-numeric is a broken read, not a timestamp. Without the numeric test, bash's `>=` on a string would
# either error under `set -e` or compare as zero, and a zero compares older than any real mark by luck rather than by
# intent.
RECEIPT_OUT="not-a-timestamp"
uat_wait_for_pkg_receipt vm com.fleetdm.edr.agent 1000 1 && got=0 || got=1
check "rejects a malformed receipt value" "1" "$got"

# A non-numeric mark is what a failed VM clock read produces. It must refuse rather than certify: the old fallback of 0
# is older than every receipt, so the PREVIOUS install's receipt proved the current one, which is the false positive the
# receipt check exists to prevent.
RECEIPT_OUT="2000"
uat_wait_for_pkg_receipt vm com.fleetdm.edr.agent "" 1 >/dev/null 2>&1 && got=0 || got=1
check "refuses an empty install mark" "1" "$got"
uat_wait_for_pkg_receipt vm com.fleetdm.edr.agent "[driver] DRY-RUN ssh" 1 >/dev/null 2>&1 && got=0 || got=1
check "refuses a non-numeric install mark" "1" "$got"

# The helper must ask about the package it was given, not a hardcoded one.
RECEIPT_OUT="2000"
uat_wait_for_pkg_receipt vm com.example.other 1000 1 >/dev/null
check "queries the package id it was passed" "1" "$(grep -c 'com.example.other' "$RECEIPT_SAW")"

unset -f sleep uat_ssh

echo
echo "ran $TESTS_RUN checks, $TESTS_FAILED failed"
[[ "$TESTS_FAILED" -eq 0 ]]
