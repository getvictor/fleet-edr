#!/usr/bin/env bash
#
# VM-side reproduction for T1562.001 (T1562.001-sensor-tamper).
#
# Detection target: catalog rule sensor_tamper.
#
# Unlike the other corpus attack.sh files, this one is NOT a placeholder: the
# real, asserted VM driver exists and is wired into the L5 harness at
# scripts/uat/scenarios/sensor-tamper/. Run it with:
#
#   task uat:l5 -- sensor-tamper --skip-install    # dash-lint:ignore (task end-of-options separator)
#
# (see that scenario's README.md for the required env and VM prerequisites).
#
# This file stays here because the corpus convention is one attack.sh per
# technique directory, and because the one-line reproduction is worth having
# next to the synthetic scenario it complements:
#
#   sudo "/Applications/Fleet EDR.app/Contents/MacOS/edr" disable-filter
#
# The agent's self-heal restores capture about 35 seconds later, which is
# exactly why the alert has to exist: host health reads healthy again and
# keeps no record that anything happened.
#
# Executing this file directly does the tamper and nothing else: no assertions,
# and no wait for the repair. Prefer the L5 scenario, which asserts the alert
# server-side and leaves the host capturing.

set -eEuo pipefail

echo "[T1562.001-sensor-tamper] the asserted driver is: task uat:l5 -- sensor-tamper --skip-install" # dash-lint:ignore
echo "[T1562.001-sensor-tamper] see scripts/uat/scenarios/sensor-tamper/README.md"
exit 0
