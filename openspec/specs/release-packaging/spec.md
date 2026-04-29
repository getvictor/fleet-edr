# Release Packaging Specification

## Purpose

The release pipeline is the bridge between a tagged commit and a deployable artifact a customer can install. For a macOS
endpoint product the packaging step is the difference between an experiment and a shippable build: an unsigned, un-notarized
package will not install on a stock SIP-enabled Mac, and a signed package without the right entitlements installs but fails to
load the system extension. This specification fixes the externally-visible invariants of that pipeline so that release engineers,
auditors, and operators integrating the artifact through MDM channels (Fleet, Jamf, Kandji, Intune, mosyle) have a stable
contract to verify.

The implementation chooses specific tools (xcodebuild, pkgbuild, productbuild, codesign, notarytool, GitHub Actions); this
specification declares the externally observable outcomes those tools must produce, so the pipeline can change tools without
changing the contract.

## Requirements

### Requirement: Dry-run build on any macOS runner

The release pipeline SHALL provide a dry-run build path that exercises the full pkgbuild and productbuild script flow without
requiring Developer ID certificates, an Apple notary submission, or any release-only secret. The dry-run MUST succeed on a
stock GitHub-hosted macOS runner so that pull requests touching the packaging scaffolding catch script regressions before
release.

#### Scenario: Pull request runs the dry-run

- **GIVEN** a pull request that modifies any packaging script
- **WHEN** the dry-run workflow runs on a hosted macOS runner with no signing secrets present
- **THEN** the workflow completes without error
- **AND** the resulting `dist/` directory contains an unsigned `.pkg` whose component layout matches the production layout
  (agent component, app component, support component)

#### Scenario: Dry-run does not contact Apple

- **GIVEN** the dry-run workflow runs
- **WHEN** the build script reaches what would be the notarization or signing step in production
- **THEN** the script skips real signing and notarization and exits cleanly without attempting any network call to Apple

### Requirement: Real release build is gated to release tag refs

The release pipeline SHALL gate access to Developer ID Application and Developer ID Installer certificates, plus notarytool
credentials, behind a protected GitHub Environment that is restricted to release tag refs. A workflow run from any other ref
MUST NOT receive these secrets and MUST NOT produce a signed artifact.

#### Scenario: Tag push triggers a real build

- **GIVEN** a release tag matching the documented tag pattern is pushed
- **WHEN** the release workflow runs for that ref
- **THEN** the workflow decrypts the signing certificates from the protected environment and produces a signed, notarized
  package

#### Scenario: Manual trigger from a non-release ref does not sign

- **GIVEN** the release workflow is dispatched manually from a topic branch
- **WHEN** the workflow runs
- **THEN** the workflow runs in dry-run mode and does not access the protected signing environment

### Requirement: Hardened-runtime code signing of executables

Every Mach-O binary inside the released package SHALL be signed with the hardened runtime enabled and a secure timestamp so
that downstream XPC peer validation, the macOS notary, and Gatekeeper accept the artifact at install and run time. The host
app, the system extension bundle, and the network extension bundle (when present) MUST each be signed with their respective
entitlements applied so that restricted entitlements take effect on SIP-enabled hosts.

#### Scenario: Notary accepts the package

- **GIVEN** a real release build of a tagged commit
- **WHEN** the package is submitted to the Apple notary
- **THEN** the notary accepts the submission

#### Scenario: System extension activates on a SIP-enabled host

- **GIVEN** a SIP-enabled macOS host that has installed the released package
- **WHEN** the host app requests activation of the system extension
- **THEN** activation succeeds (the per-bundle entitlements that the activation depends on are present in the signed bundle)

### Requirement: Notarization and stapling

A real release build SHALL submit the final installer package to the Apple notary, wait for acceptance, and staple the
notarization ticket to the package so that Gatekeeper can validate the package offline at install time. A package that has not
been stapled MUST NOT be published.

#### Scenario: Released package is stapled

- **GIVEN** a notarized installer package
- **WHEN** the build script completes
- **THEN** the package carries a stapled notarization ticket
- **AND** offline Gatekeeper validation of the package succeeds

### Requirement: Final artifact naming

The release pipeline SHALL produce a final installer artifact at `dist/fleet-edr-<version>.pkg` where `<version>` is derived
from the release tag. When the tag contains characters not safe in a filename, those characters MUST be replaced with `-` so
the resulting path is a single regular file.

#### Scenario: Versioned package name

- **GIVEN** a release tag `v1.2.3`
- **WHEN** the build completes
- **THEN** the final artifact path is `dist/fleet-edr-v1.2.3.pkg`

#### Scenario: Tag with a path-separator character

- **GIVEN** a release tag `release/v1.2`
- **WHEN** the build completes
- **THEN** the final artifact path is `dist/fleet-edr-release-v1.2.pkg`

### Requirement: Mobile configuration profiles ship alongside the package

The release pipeline SHALL produce two `.mobileconfig` profiles that operators install alongside the package: one that
pre-approves the system extension so end users do not see the load-time approval prompt, and one that grants the agent the
TCC Full Disk Access entitlement it needs to read system telemetry. Both profiles MUST be rendered with the project's team id
substituted into the template, and on a real release MUST be signed with the Developer ID Installer identity so MDM
channels accept them as managed configuration.

#### Scenario: Profiles are rendered and signed on a real release

- **GIVEN** a real release build
- **WHEN** the profile signing step runs
- **THEN** the build produces `edr-system-extension.mobileconfig` and `edr-tcc-fda.mobileconfig`, each signed by the Developer
  ID Installer identity

#### Scenario: Profiles are rendered without signing on a dry-run

- **GIVEN** a dry-run build
- **WHEN** the profile rendering step runs
- **THEN** the build produces the two `.mobileconfig` files unsigned, with the team id substituted

### Requirement: Uninstall path is deliverable

The released package SHALL include an uninstall script that an operator (or the customer's MDM) can invoke to remove the agent,
the host app, and the system extension cleanly from a host without requiring the original package. The uninstall path is part
of the product contract; an installer that cannot be cleanly uninstalled is not shippable.

#### Scenario: Operator runs the uninstall script

- **GIVEN** a host on which the released package was installed
- **WHEN** the operator runs the bundled uninstall script as root
- **THEN** the script stops and unloads the agent's launch daemon, deactivates the system extension, and removes the agent's
  binaries and runtime state
