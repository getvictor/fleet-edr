#!/usr/bin/env bash
#
# L5 VM-driver placeholder for T1548.003 (T1548.003-sudoers-tamper).
#
# Detection target: catalog rule sudoers_tamper.
#
# What the real VM equivalent looks like: echo '# synthetic' | sudo tee /etc/sudoers.d/synth (write-mode open against sudoers path). Drop the file on cleanup.
#
# When the M11 self-hosted runner lands, this script will be invoked by
# scripts/uat/system-test.sh against the edr-qa VM. Until then it exists
# to document the intended VM-side reproduction; the L6 nightly runs
# entirely synthetically via scenario.yaml + the fakeagent library, so
# this file is not currently executed by any harness.

set -eEuo pipefail

echo "[T1548.003-sudoers-tamper] L5 driver not wired yet; this is a placeholder."
echo "[T1548.003-sudoers-tamper] See scripts/qa/attack-runbook.sh for the closest existing real-VM equivalent."
exit 0
