#!/usr/bin/env bash
#
# L5 VM-driver placeholder for T1546.016 (T1546.016-unsigned-installer-package).
#
# Detection target: catalog rule installer_unsigned_package.
#
# What the real VM equivalent looks like: build an unsigned package with a postinstall script (pkgbuild --scripts, no
# --sign) and install it as root with `installer -pkg <pkg> -target /`.
#
# When the M11 self-hosted runner lands, this script will be invoked by
# scripts/uat/system-test.sh against the edr-qa VM. Until then it exists
# to document the intended VM-side reproduction; the L6 nightly runs
# entirely synthetically via scenario.yaml + the fakeagent library, so
# this file is not currently executed by any harness.

set -eEuo pipefail

echo "[T1546.016-unsigned-installer-package] L5 driver not wired yet; this is a placeholder."
exit 0
