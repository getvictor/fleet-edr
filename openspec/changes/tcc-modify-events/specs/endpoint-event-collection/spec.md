## ADDED Requirements

### Requirement: TCC permission changes are reported

The security extension SHALL emit a `tcc_modify` event when macOS reports that a TCC permission record was created, modified or deleted. The payload SHALL carry the service, the identity of the app the permission is about and its identity type, the update type, the resulting right, the reason, and the instigating process's pid and code signing, with the responsible process's pid and code signing when macOS reports one. The identity type, update type, right and reason SHALL be sent as names, and a value the extension does not know SHALL be sent as `unknown`.

#### Scenario: The change is named in words

- **GIVEN** a TCC modification whose SDK values are a bundle identifier, a deletion, an unknown right and no reason
- **WHEN** the extension serializes it
- **THEN** the payload says `bundle_id`, `delete`, `unknown` and `none`, and a reason value past the SDK's last known case is sent as `unknown`
