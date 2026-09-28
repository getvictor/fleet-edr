#!/usr/bin/env bash
#
# L5 VM-driver placeholder for T1547.015 (T1547.015-login-item-persistence).
#
# Detection target: catalog rule persistence_login_item.
#
# What the real VM equivalent looks like: an app with an ad-hoc signed helper in Contents/Library/LoginItems/ calls
# SMAppService.loginItem(identifier:).register() as the GUI user; unregister() removes it.
#
# When the M11 self-hosted runner lands, this script will be invoked by
# scripts/uat/system-test.sh against the edr-qa VM. Until then it exists
# to document the intended VM-side reproduction; the L6 nightly runs
# entirely synthetically via scenario.yaml + the fakeagent library, so
# this file is not currently executed by any harness.

set -eEuo pipefail

echo "[T1547.015-login-item-persistence] L5 driver not wired yet; this is a placeholder."
exit 0
