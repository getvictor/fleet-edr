# Waive an installer script by the team that signed its package

## Why

Installing any `.pkg` raises `suspicious_exec`, and no exclusion could silence it without blinding the rule to malicious installer scripts (issue #1161). PackageKit runs every package's scripts under its own `package_script_service`, so every match type the rule reads names Apple's installer: excluding it trusts every package. The agent now attaches the signature of the package a script belongs to (the `package_signing` field on the script's exec, from the change that shipped the agent half).

## What changes

- A new exclusion match type, `package_team_id`: the Developer ID team that signed an installer package, distinct from `team_id`, which names the team that signed a process. The detection-config column accepts it (migration 00010).
- `suspicious_exec` consults it for an installer script, and only when the chain's parent is `package_script_service` and the package is signed by a certificate macOS trusts. An unsigned package, or one whose certificate is not trusted, cannot be waived this way.
- The alert names the package being installed and who signed it.

## Limits

The signature narrows an alert an operator chose to exclude; it never raises trust on its own, since a root-run preinstall can in rare cases redirect what the agent reads. A script that runs a second program out of a temporary path is still reported. `shell_network_connect` does not consult it, since its trigger, a connection, carries no package signature.
