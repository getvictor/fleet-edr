# Release packaging: an installable dry-run package delta

## ADDED Requirements

### Requirement: The packaged app and extensions carry the entitlements they need to activate

The build SHALL sign the host app and both system extensions with their entitlements in EVERY build mode, and SHALL fail if any of the three is missing the entitlement that makes it usable.

This is the only place those entitlements are applied. The Xcode project sets none, so every bundle it produces carries `get-task-allow` alone: an app without `com.apple.developer.system-extension.install` cannot submit an activation request, and an extension that declares no category is rejected by the operating system as not belonging to any extension category. Both failures appear only when somebody installs the package and watches activation fail, and the platform reports the reason in a form that is redacted by default, so the build MUST assert the entitlements rather than assume the signing step ran.

Restricted entitlements additionally require an embedded provisioning profile to be honoured on a host with System Integrity Protection enabled. Profiles are issued per signing identity, so a package built without release credentials cannot carry them, and such a package is usable only where those entitlements are not enforced.

#### Scenario: Every build mode applies the entitlements

- **GIVEN** a package built without release signing credentials
- **WHEN** the build completes
- **THEN** the host app is signed with the system-extension install entitlement
- **AND** each system extension is signed with the entitlement that declares its category

#### Scenario: A bundle missing its entitlement fails the build

- **GIVEN** a build in which one of the three bundles is signed without its entitlement
- **WHEN** the build reaches the entitlement check
- **THEN** the build fails and names the bundle and the missing entitlement

### Requirement: A package built for testing replaces what is already installed

A package built without release signing credentials SHALL replace the installed application regardless of the version already present.

Such a package is a test artifact for a development host, and it carries whatever version the local build produced rather than a release version. Under the version-checking the released package relies on, installing one over an existing install skips the application while still replacing the agent, and the installer reports success: the host is left running a new agent against the previously installed application and extensions. A mixed install that reports success is worse than a refused one, because nothing surfaces it.

The released package SHALL keep version-checking, so a genuine upgrade replaces the application only when its version moves.

#### Scenario: A test package installs over an existing install

- **GIVEN** a host with the application already installed
- **WHEN** a package built without release signing credentials is installed, whatever version it carries
- **THEN** the installed application is replaced by the one in the package
