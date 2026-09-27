## ADDED Requirements

### Requirement: An installer script names its package's signature

The agent SHALL attach to the exec of a package installer script the signature of the package the script belongs to: whether it is signed by a certificate macOS trusts, whether Apple's notary service accepted it, and the Developer ID team that signed it. The package is the one named by the script's first argument, which is where PackageKit passes it.

The agent SHALL do so only when the exec's parent is Apple's `package_script_service`, since the argument can be written by anyone and would otherwise let a script claim a signed package's identity. When the package cannot be read, the exec SHALL carry no package signature rather than one reporting it unsigned. The signature is read after the script has started, so a package changed after PackageKit prepared the install SHALL also leave the exec without one, since the file read may no longer be the package being installed. Only a signature macOS accepts SHALL be reported as signed, and a team SHALL be reported only from a Developer ID Installer certificate.

#### Scenario: A script PackageKit ran carries its package's signature

- **GIVEN** an exec whose parent is `package_script_service` and whose script runs out of PackageKit's sandbox with a package path as its first argument
- **WHEN** the agent enriches the event
- **THEN** the exec carries that package's signature

#### Scenario: A script from another parent carries none

- **GIVEN** an exec whose arguments name a signed vendor package after a sandbox-shaped script path, but whose parent is a shell
- **WHEN** the agent enriches the event
- **THEN** the exec carries no package signature and the package is not read

#### Scenario: An unreadable package is not reported as unsigned

- **GIVEN** an installer script's exec whose package can no longer be read
- **WHEN** the agent enriches the event
- **THEN** the exec carries no package signature

#### Scenario: A package changed during the install is not classified

- **GIVEN** an installer script's exec whose package file was replaced after PackageKit created the install sandbox
- **WHEN** the agent enriches the event
- **THEN** the exec carries no package signature
