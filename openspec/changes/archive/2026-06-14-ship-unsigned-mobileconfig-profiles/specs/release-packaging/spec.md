# Release packaging: unsigned mobileconfig profiles delta

## MODIFIED Requirements

### Requirement: Mobile configuration profiles ship alongside the package

The release pipeline SHALL produce two `.mobileconfig` profiles that operators upload to their MDM alongside the package: one that pre-approves the system extension so end users do not see the load-time approval prompt, and one that grants the agent the TCC Full Disk Access entitlement it needs to read system telemetry. Both profiles MUST be rendered with the project's team id substituted into the template, and MUST ship unsigned (plain XML, no CMS wrapper). The payloads are MDM-only, every supported MDM channel (Fleet, Jamf, Kandji, Intune, mosyle) signs profiles itself at delivery time, and Fleet rejects a pre-signed upload; download authenticity is provided by the cosign signature attached to each released artifact, not by a CMS signature on the profile.

#### Scenario: Profiles are rendered unsigned

- **GIVEN** a release build (real or dry-run)
- **WHEN** the profile render step runs
- **THEN** the build produces `edr-system-extension.mobileconfig` and `edr-tcc-fda.mobileconfig` with the team id substituted
- **AND** each profile is plain XML with no CMS signature, accepted verbatim by an MDM that signs at delivery time
