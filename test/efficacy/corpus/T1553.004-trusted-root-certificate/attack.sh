#!/usr/bin/env bash
#
# L5 VM-driver placeholder for T1553.004 (T1553.004-trusted-root-certificate).
#
# Detection target: catalog rule trusted_root_certificate.
#
# What the real VM equivalent looks like: generate a self-signed certificate with openssl and trust it with
# `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <cert>`, then remove it with
# `sudo security remove-trusted-cert -d <cert>`.
#
# When the M11 self-hosted runner lands, this script will be invoked by
# scripts/uat/system-test.sh against the edr-qa VM. Until then it exists
# to document the intended VM-side reproduction; the L6 nightly runs
# entirely synthetically via scenario.yaml + the fakeagent library, so
# this file is not currently executed by any harness.

set -eEuo pipefail

echo "[T1553.004-trusted-root-certificate] L5 driver not wired yet; this is a placeholder."
exit 0
