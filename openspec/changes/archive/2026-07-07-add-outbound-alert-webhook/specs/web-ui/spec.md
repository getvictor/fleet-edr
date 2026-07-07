## ADDED Requirements

### Requirement: The settings area manages webhook destinations

The web UI SHALL provide a Webhooks section in the admin settings area that lists destinations and offers controls to add, edit, disable, delete, and test a destination, and that shows recent per-destination delivery outcomes. The section and its controls SHALL be gated on the operator's `webhook.manage` permission via the `useCan()` seam: an operator lacking the grant SHALL NOT see the section. The signing secret SHALL be entered write-only and SHALL NOT be displayed after it is saved.

#### Scenario: An admin adds a destination from the settings area

- **GIVEN** an admin viewing the settings area who holds `webhook.manage`
- **WHEN** they open the Webhooks section, add a destination with a URL and secret, and submit
- **THEN** the destination is sent to the configuration API and the refreshed list shows it without its secret

#### Scenario: An operator tests a destination from the UI

- **GIVEN** an admin viewing the Webhooks section
- **WHEN** they trigger a test delivery for a destination
- **THEN** the immediate outcome is shown in the UI

#### Scenario: The Webhooks section is hidden without the manage grant

- **GIVEN** an operator viewing the settings area who does not hold `webhook.manage`
- **WHEN** the settings area renders
- **THEN** the Webhooks section is not shown

#### Scenario: The secret field is write-only

- **GIVEN** an admin editing an existing destination
- **WHEN** the edit form renders
- **THEN** the signing-secret field is empty rather than prefilled from the server
