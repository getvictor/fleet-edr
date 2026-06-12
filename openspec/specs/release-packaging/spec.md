# Release Packaging Specification

## Purpose

The release pipeline is the bridge between a tagged commit and a deployable artifact a customer can install. For a macOS endpoint product the packaging step is the difference between an experiment and a shippable build: an unsigned, un-notarized package will not install on a stock SIP-enabled Mac, and a signed package without the right entitlements installs but fails to load the system extension. This specification fixes the externally-visible invariants of that pipeline so that release engineers, auditors, and operators integrating the artifact through MDM channels (Fleet, Jamf, Kandji, Intune, mosyle) have a stable contract to verify.

The implementation chooses specific tools (xcodebuild, pkgbuild, productbuild, codesign, notarytool, GitHub Actions); this specification declares the externally observable outcomes those tools must produce, so the pipeline can change tools without changing the contract.

## Requirements

### Requirement: Dry-run build on any macOS runner

The release pipeline SHALL provide a dry-run build path that exercises the full pkgbuild and productbuild script flow without requiring Developer ID certificates, an Apple notary submission, or any release-only secret. The dry-run MUST succeed on a stock GitHub-hosted macOS runner so that pull requests touching the packaging scaffolding catch script regressions before release.

#### Scenario: Pull request runs the dry-run

- **GIVEN** a pull request that modifies any packaging script
- **WHEN** the dry-run workflow runs on a hosted macOS runner with no signing secrets present
- **THEN** the workflow completes without error
- **AND** the resulting `dist/` directory contains an unsigned `.pkg` whose component layout matches the production layout (agent component, app component, support component)

#### Scenario: Dry-run does not contact Apple

- **GIVEN** the dry-run workflow runs
- **WHEN** the build script reaches what would be the notarization or signing step in production
- **THEN** the script skips real signing and notarization and exits cleanly without attempting any network call to Apple

### Requirement: Real release build is gated to release tag refs

The release pipeline SHALL gate access to Developer ID Application and Developer ID Installer certificates, plus notarytool credentials, behind a protected GitHub Environment that is restricted to release tag refs. A workflow run from any other ref MUST NOT receive these secrets and MUST NOT produce a signed artifact.

#### Scenario: Tag push triggers a real build

- **GIVEN** a release tag matching the documented tag pattern is pushed
- **WHEN** the release workflow runs for that ref
- **THEN** the workflow decrypts the signing certificates from the protected environment and produces a signed, notarized package

#### Scenario: Manual trigger from a non-release ref does not sign

- **GIVEN** the release workflow is dispatched manually from a topic branch
- **WHEN** the workflow runs
- **THEN** the workflow runs in dry-run mode and does not access the protected signing environment

### Requirement: Hardened-runtime code signing of executables

Every Mach-O binary inside the released package SHALL be signed with the hardened runtime enabled and a secure timestamp so that downstream XPC peer validation, the macOS notary, and Gatekeeper accept the artifact at install and run time. The host app, the system extension bundle, and the network extension bundle (when present) MUST each be signed with their respective entitlements applied so that restricted entitlements take effect on SIP-enabled hosts.

#### Scenario: Notary accepts the package

- **GIVEN** a real release build of a tagged commit
- **WHEN** the package is submitted to the Apple notary
- **THEN** the notary accepts the submission

#### Scenario: System extension activates on a SIP-enabled host

- **GIVEN** a SIP-enabled macOS host that has installed the released package
- **WHEN** the host app requests activation of the system extension
- **THEN** activation succeeds (the per-bundle entitlements that the activation depends on are present in the signed bundle)

### Requirement: Notarization and stapling

A real release build SHALL submit the final installer package to the Apple notary, wait for acceptance, and staple the notarization ticket to the package so that Gatekeeper can validate the package offline at install time. A package that has not been stapled MUST NOT be published.

#### Scenario: Released package is stapled

- **GIVEN** a notarized installer package
- **WHEN** the build script completes
- **THEN** the package carries a stapled notarization ticket
- **AND** offline Gatekeeper validation of the package succeeds

### Requirement: Final artifact naming

The release pipeline SHALL produce a final installer artifact at `dist/fleet-edr-<version>.pkg` where `<version>` is derived from the release tag. When the tag contains characters not safe in a filename, those characters MUST be replaced with `-` so the resulting path is a single regular file.

#### Scenario: Versioned package name

- **GIVEN** a release tag `v1.2.3`
- **WHEN** the build completes
- **THEN** the final artifact path is `dist/fleet-edr-v1.2.3.pkg`

#### Scenario: Tag with a path-separator character

- **GIVEN** a release tag `release/v1.2`
- **WHEN** the build completes
- **THEN** the final artifact path is `dist/fleet-edr-release-v1.2.pkg`

### Requirement: Mobile configuration profiles ship alongside the package

The release pipeline SHALL produce two `.mobileconfig` profiles that operators upload to their MDM alongside the package: one that pre-approves the system extension so end users do not see the load-time approval prompt, and one that grants the agent the TCC Full Disk Access entitlement it needs to read system telemetry. Both profiles MUST be rendered with the project's team id substituted into the template, and MUST ship unsigned (plain XML, no CMS wrapper). The payloads are MDM-only, every supported MDM channel (Fleet, Jamf, Kandji, Intune, mosyle) signs profiles itself at delivery time, and Fleet rejects a pre-signed upload; download authenticity is provided by the cosign signature attached to each released artifact, not by a CMS signature on the profile.

#### Scenario: Profiles are rendered unsigned

- **GIVEN** a release build (real or dry-run)
- **WHEN** the profile render step runs
- **THEN** the build produces `edr-system-extension.mobileconfig` and `edr-tcc-fda.mobileconfig` with the team id substituted
- **AND** each profile is plain XML with no CMS signature, accepted verbatim by an MDM that signs at delivery time

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

### Requirement: Uninstall path is deliverable

The released package SHALL include an uninstall script that an operator (or the customer's MDM) can invoke to remove the agent, the host app, and the system extension cleanly from a host without requiring the original package. The uninstall path is part of the product contract; an installer that cannot be cleanly uninstalled is not shippable.

#### Scenario: Operator runs the uninstall script

- **GIVEN** a host on which the released package was installed
- **WHEN** the operator runs the bundled uninstall script as root
- **THEN** the script stops and unloads the agent's launch daemon, deactivates the system extension, and removes the agent's binaries and runtime state
