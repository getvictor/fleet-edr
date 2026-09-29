#!/usr/bin/env bash
#
# L5 VM-driver placeholder for T1555.003 (T1555.003-browser-credential-read).
#
# Detection target: catalog rule credential_browser_store_read.
#
# What the real VM equivalent looks like: with a browser profile present, copy its credential file with
# `cp "$HOME/Library/Application Support/Firefox/Profiles/<profile>/cookies.sqlite" /tmp/` and delete the copy.
#
# When the M11 self-hosted runner lands, this script will be invoked by
# scripts/uat/system-test.sh against the edr-qa VM. Until then it exists
# to document the intended VM-side reproduction; the L6 nightly runs
# entirely synthetically via scenario.yaml + the fakeagent library, so
# this file is not currently executed by any harness.

set -eEuo pipefail

echo "[T1555.003-browser-credential-read] L5 driver not wired yet; this is a placeholder."
exit 0
