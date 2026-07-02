## ADDED Requirements

### Requirement: Enrollment reports the agent platform

The agent SHALL include its platform in the enrollment request, one of `darwin`, `windows`, or `linux`, matching the operating system the agent runs on. The enroll endpoint SHALL reject an enrollment whose platform is present but not one of those values. The endpoint SHALL normalize an absent platform to `darwin`, the default for an agent predating this contract, and SHALL persist the platform on the enrollment record so the host inventory can surface it.

#### Scenario: The enrollment request includes the agent platform

- **GIVEN** an agent performing first-boot enrollment
- **WHEN** it posts the enrollment request
- **THEN** the request carries the agent's platform

#### Scenario: An enrollment without a platform defaults to darwin

- **GIVEN** an enrollment request that omits the platform
- **WHEN** the enroll endpoint handles it
- **THEN** the enrollment is recorded with platform `darwin`

#### Scenario: An enrollment with an unknown platform is rejected

- **GIVEN** an enrollment request whose platform is a value other than darwin, windows, or linux
- **WHEN** the enroll endpoint handles it
- **THEN** the request is rejected with a bad-body error and no enrollment is recorded
