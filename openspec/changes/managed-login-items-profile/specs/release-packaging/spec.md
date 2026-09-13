## MODIFIED Requirements

### Requirement: Mobile configuration profiles ship alongside the package

The release pipeline SHALL produce three `.mobileconfig` profiles that operators upload to their MDM alongside the package: one that pre-approves the system extension so end users do not see the load-time approval prompt, one that grants the agent the TCC Full Disk Access entitlement it needs to read system telemetry, and one that marks the product's background items as managed so a console user cannot turn off the agent daemon or the activation LaunchAgent. All three profiles MUST be rendered with the project's team id substituted into the template, and MUST ship unsigned (plain XML, no CMS wrapper). The payloads are MDM-only, every supported MDM channel (Fleet, Jamf, Kandji, Intune, mosyle) signs profiles itself at delivery time, and Fleet rejects a pre-signed upload; download authenticity is provided by the cosign signature attached to each released artifact, not by a CMS signature on the profile.

The background items profile SHALL identify the items by the team identifier rather than by label or bundle identifier, so every background item the team signs is managed, including one a later release adds. The render step SHALL refuse to produce a background items profile whose rule does not name the team identifier.

#### Scenario: Profiles are rendered unsigned

- **GIVEN** a release build (real or dry-run)
- **WHEN** the profile render step runs
- **THEN** the build produces `edr-system-extension.mobileconfig`, `edr-tcc-fda.mobileconfig` and `edr-login-items.mobileconfig` with the team id substituted
- **AND** each profile is plain XML with no CMS signature, accepted verbatim by an MDM that signs at delivery time

#### Scenario: The background items profile manages the team's items

- **GIVEN** a release build rendering its profiles
- **WHEN** the background items profile is rendered
- **THEN** it carries one managed login items rule, of type team identifier, naming the project's team id
- **AND** the render step fails if the rendered rule names another type or team
