## Why

Installer packages (MITRE T1546.016) are one of the macOS techniques issue #1167 lists as uncovered. A package's preinstall and postinstall run as root, so a package a user is talked into opening runs its payload with full privilege. `suspicious_exec` already reports each installer script, and since the agent attaches the package's signature it can be excluded by the team that signed the package. That leaves no rule that singles out the package worth alerting on regardless of tuning: one that is unsigned, or whose signature macOS does not trust. Vendors sign their packages, and macOS refuses an unsigned one unless the user overrides it.

## What changes

- A new rule, `installer_unsigned_package` (high), fires when an installer script runs from a package that is unsigned or untrusted, read from the package signature the agent attaches to the script's exec.
- One alert per package: a package's scripts share its path as their dedup subject, and the alert opens on the first script's process.
- An operator waives an unsigned in-house package by a path glob on the package; an unsigned package names no team to trust it by.
- The fake agent can attach a package signature to an exec, so the efficacy corpus exercises the rule.

## Not changed

`suspicious_exec` still reports every installer script, and its `package_team_id` exclusion is unchanged. An agent that does not attach package signatures produces nothing for this rule.
