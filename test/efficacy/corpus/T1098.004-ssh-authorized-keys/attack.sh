#!/usr/bin/env bash
#
# L5 VM-driver placeholder for T1098.004 (T1098.004-ssh-authorized-keys).
#
# Detection target: catalog rule persistence_ssh_authorized_keys.
#
# What the real VM equivalent looks like: append a public key to ~/.ssh/authorized_keys as the user
# (`echo ssh-ed25519 ... >> ~/.ssh/authorized_keys`), then remove the line.
#
# When the M11 self-hosted runner lands, this script will be invoked by
# scripts/uat/system-test.sh against the edr-qa VM. Until then it exists
# to document the intended VM-side reproduction; the L6 nightly runs
# entirely synthetically via scenario.yaml + the fakeagent library, so
# this file is not currently executed by any harness.

set -eEuo pipefail

echo "[T1098.004-ssh-authorized-keys] L5 driver not wired yet; this is a placeholder."
exit 0
