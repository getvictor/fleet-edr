## Why

Installing a root certificate (MITRE T1553.004) is one of the macOS techniques issue #1167 lists as uncovered, and no vendored Sigma rule covers it. A certificate the host trusts as a root lets whoever holds its key intercept the host's TLS connections or sign code it will accept. The sensor already reports the `security` exec that writes the trust setting, with its argv.

## What changes

- A new rule, `trusted_root_certificate` (high), fires on `/usr/bin/security` with the subcommand `add-trusted-cert` or `trust-settings-import`. Its logic is a detection block in its pack file.
- It has no exclusions: the process is always Apple's `security` and its parent usually a shell. A host that deploys roots this way runs the rule in monitor.

## Not changed

A trust setting written through the Security framework by a program of its own, and a certificate installed by a configuration profile, are not reported.
