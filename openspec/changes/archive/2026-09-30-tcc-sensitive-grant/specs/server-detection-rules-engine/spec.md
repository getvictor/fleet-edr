## ADDED Requirements

### Requirement: A sensitive TCC grant is reported

The `tcc_sensitive_grant` rule SHALL fire on a `tcc_modify` event whose update type is `create` or `modify`, whose right is `allowed`, and whose service is `SystemPolicyAllFiles`, `Accessibility`, `ScreenCapture`, `ListenEvent` or `PostEvent`, when the event carries the app's code signing and the app is not an Apple platform binary. It SHALL NOT fire when the reason is `mdm_policy`, or when the event carries no code signing for the app. The finding SHALL name the app and the permission in the words System Settings uses, carry no process, and deduplicate per app and service. An exclusion for the rule SHALL suppress it by the app's team, its team-qualified signing identifier, or a path glob on its path.

#### Scenario: A sensitive permission granted to another vendor's app fires

- **GIVEN** Full Disk Access, Accessibility, Screen Recording, Input Monitoring or input-event posting granted to Firefox, signed by Mozilla's team, as System Settings records it (a modify, right `allowed`, reason `user_set`), and Full Disk Access created for an executable path
- **WHEN** detection evaluates each event
- **THEN** `tcc_sensitive_grant` raises a medium-severity finding naming the app and the permission, with no process

#### Scenario: Other changes do not fire

- **GIVEN** a denial, a deletion, a grant of a service that is not sensitive, a grant made by an MDM profile, a grant to an Apple platform binary, and a grant to an app whose signature could not be read
- **WHEN** detection evaluates the events
- **THEN** no finding is raised

#### Scenario: A granted app is waived by its signer or path

- **GIVEN** an exclusion for the rule naming the app's team, its team-qualified signing identifier, or its path
- **WHEN** detection evaluates the grant
- **THEN** no finding is raised
- **AND** the same team excluded only for another rule does not suppress it
