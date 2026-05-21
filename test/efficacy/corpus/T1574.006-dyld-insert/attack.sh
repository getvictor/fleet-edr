#!/usr/bin/env bash
#
# L5 VM-driver placeholder for T1574.006 (T1574.006-dyld-insert).
#
# Detection target: catalog rule dyld_insert.
#
# What the real VM equivalent looks like: env DYLD_INSERT_LIBRARIES=/tmp/payload.dylib /usr/bin/true -- see scripts/qa/attack-runbook.sh step 'dyld_insert'.
#
# When the M11 self-hosted runner lands, this script will be invoked by
# scripts/uat/system-test.sh against the edr-qa VM. Until then it exists
# to document the intended VM-side reproduction; the L6 nightly runs
# entirely synthetically via scenario.yaml + the fakeagent library, so
# this file is not currently executed by any harness.

set -eEuo pipefail

echo "[T1574.006-dyld-insert] L5 driver not wired yet; this is a placeholder."
echo "[T1574.006-dyld-insert] See scripts/qa/attack-runbook.sh for the closest existing real-VM equivalent."
exit 0
