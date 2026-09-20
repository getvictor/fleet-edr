# A managed login items profile keeps the agent's background items on

Issue #358. The agent daemon (`com.fleetdm.edr.agent`) and the activation LaunchAgent (`com.fleetdm.edr.activate`) are ordinary background items. On macOS 13 and later a console user can turn either off in System Settings > General > Login Items & Extensions, which silently stops the agent or the re-activation that follows an upgrade.

## What changes

- **A third profile, `edr-login-items.mobileconfig`**, rendered by `packaging/profiles/render.sh` with the other two and shipped the same way: unsigned, since the MDM signs at delivery. A `com.apple.servicemanagement` payload with one `TeamIdentifier` rule for the team marks every background item the team signs as managed. The daemon and the LaunchAgent cannot be turned off, and a background item added later is covered without a profile change.
- **`render.sh` reads the rule back** from the rendered file and fails unless there is exactly one `TeamIdentifier` rule for the team id. `plutil -lint` accepts a profile that would install and manage nothing.
- **The release publishes it** like the other profiles: listed in `SHA256SUMS`, signed with cosign, attested, and uploaded to the GitHub Release. The verify-release skill expects the extra artifact.
- **Docs**: the MDM and Fleet deployment guides add the profile to the artifacts and steps, and the changelog tells operators to upload it.
