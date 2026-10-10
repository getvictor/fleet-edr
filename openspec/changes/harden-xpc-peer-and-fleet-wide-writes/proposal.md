## Why

Two trust gaps found by the 2026-10-08 threat-model refresh:

- **Team ID was the extensions' only XPC check.** Their release builds accepted any binary signed with the Fleet team ID. That channel now carries containment state, application-control rules and watched paths, so any binary the team ever signed could lift containment or rewrite the blocklist.
- **Fleet-wide writes skipped fresh sign-in.** Rule content and detection tuning (exclusions, rule modes, watched paths) can blind detection across the whole fleet, but a stale session could change them. Editing the reachable-address set already required a fresh sign-in for the same reason. Revoking a host's enrollment was listed as destructive in the authentication spec, but the policy did not gate it.

## What changes

- A release-built extension accepts an XPC peer only if it chains to the Apple anchor, carries the Fleet team ID, AND is signed with the agent's identifier `fleet-edr-agent`, which the release package already sets.
- A fresh sign-in within the reauth window is required for `rule_content.write`, `detection_config.write` and `enrollment.revoke`, alongside the host commands and `containment_config.write`. The detection-tuning page and the watched-paths editor prompt for it and retry the change. Service-account tokens are exempt, as they are for every reauth-gated action.

## Not changed

Debug builds still accept the ad-hoc dev agent by its identifier. Read access and role grants are unchanged.
