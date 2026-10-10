## ADDED Requirements

### Requirement: The installer refuses a macOS the bundles cannot run on

The installer SHALL refuse to install on a Mac whose macOS version is older than the deployment target the app and both system extensions are built for, and SHALL name the required macOS version in the refusal. The installer minimum and the deployment target MUST be the same version, so no Mac can install a package it cannot run. The supported floor is macOS 26.0 on Apple Silicon.

#### Scenario: The installer minimum matches the deployment target

- **GIVEN** the app and both extensions are built for one macOS deployment target
- **WHEN** the release package is assembled
- **THEN** the installer's minimum macOS version equals that deployment target
- **AND** the installer's scripted version check refuses every macOS major version below it

#### Scenario: An older Mac is refused with the requirement named

- **GIVEN** a Mac running macOS 15
- **WHEN** an operator opens the release package
- **THEN** the installer refuses before installing anything
- **AND** the message says Fleet EDR requires macOS 26 (Tahoe) or later
