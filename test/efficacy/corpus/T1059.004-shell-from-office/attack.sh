#!/usr/bin/env bash
#
# L5 VM-driver placeholder for T1566.001 (T1059.004-shell-from-office).
#
# Detection target: catalog rule shell_from_office.
#
# What the real VM equivalent looks like: open a .docx with a VBA macro that calls Shell("bash -c 'curl ... | sh'"). Requires Word installed; skipped on edr-qa today (see scripts/qa/attack-runbook.sh).
#
# When the M11 self-hosted runner lands, this script will be invoked by
# scripts/uat/system-test.sh against the edr-qa VM. Until then it exists
# to document the intended VM-side reproduction; the L6 nightly runs
# entirely synthetically via scenario.yaml + the fakeagent library, so
# this file is not currently executed by any harness.

set -eEuo pipefail

echo "[T1059.004-shell-from-office] L5 driver not wired yet; this is a placeholder."
echo "[T1059.004-shell-from-office] See scripts/qa/attack-runbook.sh for the closest existing real-VM equivalent."
exit 0
