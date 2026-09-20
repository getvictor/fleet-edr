## ADDED Requirements

### Requirement: Watched-path replacements guard against lost updates

`PUT /api/v1/detection-config/watched-paths` SHALL accept an optional `expected_version`, the version the caller's edit started from. When it is present and the stored set is at any other version, the server SHALL refuse the replacement with status 409 and the error code `detection_config.conflict`, naming the current version, and SHALL store nothing, queue nothing, and audit nothing. The comparison SHALL be made under the same lock as the replacement, so two replacements naming the same version cannot both succeed. A request without `expected_version` SHALL replace whatever is stored.

#### Scenario: A replacement based on an outdated set is refused

- **GIVEN** a stored set at version 1
- **WHEN** a caller permitted `detection_config.write` submits a replacement naming `expected_version` 0
- **THEN** it is refused with 409 and `detection_config.conflict`, and the message names version 1
- **AND** the stored set is unchanged, and no command is queued and no change audited
- **AND** of two replacements submitted together naming `expected_version` 1, exactly one is stored

### Requirement: The watched-path set names who last changed it

The watched-path GET and PUT responses SHALL carry `updated_by_label`, the display label resolved from `updated_by` when the response is written (a user's email, a service account's name, or `system`). It SHALL be absent for the set no one has changed and when the principal cannot be resolved, in which case clients fall back to `updated_by`.

#### Scenario: The set names its last changer by label

- **GIVEN** a set last changed by a user, and a set last changed by a principal that has since been deleted
- **WHEN** a caller reads each set, and when a user replaces a set
- **THEN** the response names the user by email for the first read and for the replacement
- **AND** carries no label for the deleted principal or for the set no one has changed
