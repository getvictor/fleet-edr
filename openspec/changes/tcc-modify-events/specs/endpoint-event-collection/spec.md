## ADDED Requirements

### Requirement: TCC permission changes are reported

The security extension SHALL emit a `tcc_modify` event when macOS reports that a TCC permission record was created, modified or deleted. The payload SHALL carry the service, the identity of the app the permission is about and its identity type, the update type, the resulting right, the reason, and the instigating process's pid. It SHALL carry the instigating process's code signing when macOS reports that process, the responsible process's pid when macOS reports a responsible audit token, and the responsible process's code signing when macOS reports that process; each is omitted, not sent as null, when absent. The agent SHALL add the app's path and its on-disk code signing, as `identity_path` and `identity_code_signing`, when the identity is an executable path, or a bundle identifier for which LaunchServices has an application, and the app can be read; otherwise it SHALL leave both out. When several installed copies share the bundle identifier, the agent SHALL report the least trusted readable one: the first whose signature is not an Apple platform binary's, or Apple's only when every readable copy is. The identity type, update type, right and reason SHALL be sent as names, and a value the extension does not know SHALL be sent as `unknown`.

#### Scenario: The change is named in words

- **GIVEN** a TCC modification whose SDK values are a bundle identifier, a deletion, an unknown right and no reason
- **WHEN** the extension serializes it
- **THEN** the payload says `bundle_id`, `delete`, `unknown` and `none`, and a reason value past the SDK's last known case is sent as `unknown`

#### Scenario: The app a permission is about carries its signature

- **GIVEN** a `tcc_modify` whose identity is a bundle identifier LaunchServices knows, one whose identity is an executable path, and one whose identity no app claims
- **WHEN** the agent enriches the events
- **THEN** the first two carry the app's path and its code signing, and the third carries neither
- **AND** when an Apple copy and a copy that is not Apple's share one identifier, the copy that is not Apple's is reported
