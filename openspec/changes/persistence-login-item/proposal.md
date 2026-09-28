## Why

Nothing judged login-item persistence (MITRE T1547.015), one of the macOS techniques issue #1167 lists as uncovered. A helper that an app registers as a login item launches at every login, the same persistence a LaunchAgent gives, but through Background Task Management's `login_item` type, which no rule read.

## What changes

- A new rule, `persistence_login_item`, fires on a login-item registration whose app is not an Apple platform binary and not MDM-managed. It judges both shapes Background Task Management reports: a helper an app registers from inside its bundle (`login_item`), and an app added to the user's login items, by itself through `SMAppService` or through the legacy login-items list (`app`). It shares its gate with `persistence_launchagent` and `privilege_launchd_plist_write`: the decision rides the helper's code signature, not the app that registered it.
- An operator waives a vendor by the helper's team or team-qualified signing identifier, or an unsigned in-house app by the helper bundle's path.

## Not changed

The rule needs the agent to send the helper's signature, which an agent from before this release does not; such a registration is skipped. A registration reported as a user item is not judged; no route to adding a login item that was tested produces one.
