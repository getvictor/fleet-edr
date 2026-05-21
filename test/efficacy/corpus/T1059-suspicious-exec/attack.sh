#!/usr/bin/env bash
#
# L5 VM-driver placeholder for T1059 (T1059-suspicious-exec).
#
# Detection target: catalog rule suspicious_exec.
#
# What the real VM equivalent looks like: python3 -c on /tmp dropper then exec /bin/sh /tmp/payload -- see scripts/qa/attack-runbook.sh step 'suspicious_exec'.
#
# When the M11 self-hosted runner lands, this script will be invoked by
# scripts/uat/system-test.sh against the edr-qa VM. Until then it exists
# to document the intended VM-side reproduction; the L6 nightly runs
# entirely synthetically via scenario.yaml + the fakeagent library, so
# this file is not currently executed by any harness.

set -eEuo pipefail

echo "[T1059-suspicious-exec] L5 driver not wired yet; this is a placeholder."
echo "[T1059-suspicious-exec] See scripts/qa/attack-runbook.sh for the closest existing real-VM equivalent."
exit 0
