# release-packaging (delta)

## MODIFIED Requirements

### Requirement: Uninstall path is deliverable

The released package SHALL include an uninstall script that an operator (or the customer's MDM) can invoke to remove the agent, the host app, and the system extensions cleanly from a host without requiring the original package. The uninstall path is part of the product contract; an installer that cannot be cleanly uninstalled is not shippable.

The script SHALL deactivate BOTH system extensions (Endpoint Security and Network) through the host app's `deactivate` subcommand, submitted in the logged-in user's GUI (Aqua) session via `launchctl asuser`, BEFORE it removes the app bundle. It MUST NOT use `systemextensionsctl` for deactivation: that tool has no `deactivate` subcommand and its developer commands are blocked while SIP is enabled, so the call cannot remove anything. Because the host app is the only thing that can submit an `OSSystemExtensionRequest`, the script MUST submit the deactivation while the app bundle still exists.

The script SHALL determine the actual outcome from live system-extension state rather than a command exit code, and SHALL report it truthfully: a clean removal, a removal staged for the next reboot, or extensions still active. When extensions remain active the script MUST NOT claim success; it MUST keep the host app bundle (and its uninstall script) so the operator can retry, and MUST print cause-specific guidance. In particular, on an MDM-managed host the extensions were approved by a configuration profile (`AllowedSystemExtensions`, `AllowUserOverrides=false`) and macOS refuses a local deactivation (`authorizationRequired`); removal there is achieved by the MDM removing that profile, after which macOS removes the now-unauthorized extensions, not by the local script.

#### Scenario: Operator runs the uninstall script

- **GIVEN** a host on which the released package was installed
- **WHEN** the operator runs the bundled uninstall script as root
- **THEN** the script stops and unloads the agent's launch daemon, removes the activation LaunchAgent, deactivates the system extensions through the host app, and removes the agent's binaries and runtime state

#### Scenario: Uninstall deactivates both extensions via the host app

- **GIVEN** an unmanaged host with both Fleet EDR system extensions active and a user logged in at the console
- **WHEN** the operator runs the uninstall script as root
- **THEN** the script submits `edr deactivate` in the console user's GUI session before removing the app bundle, so both the Endpoint Security and Network extensions are removed (or staged for removal on reboot)
- **AND** the script does not invoke `systemextensionsctl deactivate`

#### Scenario: Uninstall on an MDM-managed host reports the profile must be removed

- **GIVEN** an MDM-managed host whose system extensions were approved by the `com.fleetdm.edr.profile.system-extension` profile
- **WHEN** the operator runs the uninstall script as root
- **THEN** the host-app deactivation is refused by macOS (authorizationRequired) and the extensions stay active
- **AND** the script keeps the host app bundle, does not claim a clean removal, and tells the operator to remove the system-extension profile via their MDM to complete removal
