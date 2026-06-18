#!/usr/bin/env bash
#
# L5 VM-driver placeholder for T1555.001 (T1555.001-keychain-dump).
#
# Detection target: catalog rule credential_keychain_dump.
#
# What the real VM equivalent looks like: sudo security dump-keychain. See scripts/qa/attack-runbook.sh step 'credential_keychain_dump'.
#
# When the M11 self-hosted runner lands, this script will be invoked by
# scripts/uat/system-test.sh against the edr-qa VM. Until then it exists
# to document the intended VM-side reproduction; the L6 nightly runs
# entirely synthetically via scenario.yaml + the fakeagent library, so
# this file is not currently executed by any harness.

set -eEuo pipefail

echo "[T1555.001-keychain-dump] L5 driver not wired yet; this is a placeholder."
echo "[T1555.001-keychain-dump] See scripts/qa/attack-runbook.sh for the closest existing real-VM equivalent."
exit 0
