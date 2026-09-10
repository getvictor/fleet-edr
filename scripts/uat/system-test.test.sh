#!/usr/bin/env bash
#
# scripts/uat/system-test.test.sh
#
# Tests for the L5 driver's rule classification and the runbook's skip
# propagation (issues #965, #966). Runs with no VM and no server: the driver's
# --dry-run mode loads the scenario and short-circuits every remote call, which
# is enough to exercise the part that decides pass / miss / skipped.
#
# Not covered here, because a shell harness cannot honestly reach it: the
# install path itself. `uat_wait_for_pkg_receipt` is exercised against a real
# receipt on edr-qa, and the PR that added it says so.
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
echo "ran $TESTS_RUN checks, $TESTS_FAILED failed"
[[ "$TESTS_FAILED" -eq 0 ]]
