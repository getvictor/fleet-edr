# Release packaging: activate extensions on install delta

## ADDED Requirements

### Requirement: Installation activates the system extensions

The released package SHALL ship a LaunchAgent at `/Library/LaunchAgents/com.fleetdm.edr.activate.plist` that runs the host app's `activate` subcommand in the logged-in user's GUI session, and the install scripts SHALL start it so that on an MDM-managed host (system-extension profile present) the extensions reach `activated enabled` without any operator interaction: immediately when a user is logged in at install time, otherwise at the next login. Activation requests must originate from the host app in a user session (Apple's model), so the package MUST NOT rely on the root postinstall or the agent daemon to submit them, and activation failures MUST NOT fail the install. Uninstall MUST remove the LaunchAgent.

#### Scenario: Install with a user logged in activates immediately

- **GIVEN** an MDM-managed host with the system-extension profile installed and a user logged in at the console
- **WHEN** the pkg installs
- **THEN** the postinstall bootstraps the activation LaunchAgent into the console user's GUI domain
- **AND** both extensions reach `activated enabled` without any user interaction

#### Scenario: Install at the loginwindow activates at next login

- **GIVEN** an MDM-managed host with the system-extension profile installed and no user logged in
- **WHEN** the pkg installs and a user later logs in
- **THEN** the LaunchAgent runs the host app's `activate` at login and both extensions reach `activated enabled` without any user interaction

#### Scenario: Uninstall removes the activation LaunchAgent

- **GIVEN** a host where the released package is installed
- **WHEN** the operator runs the uninstall script
- **THEN** the activation LaunchAgent is booted out of the GUI domain and its plist is removed
