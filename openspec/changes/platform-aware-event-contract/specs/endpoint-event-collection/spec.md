## ADDED Requirements

### Requirement: Serialized events declare their platform

The macOS system extension serializers SHALL stamp the platform that produced the event on every event envelope they emit. Because this extension runs only on macOS, the stamped value SHALL be `darwin`, matching the server's canonical platform constant. The field is part of the platform-aware event contract so the server can scope detection rules by platform and surface it in the host inventory.

#### Scenario: An ESF event envelope carries the darwin platform

- **GIVEN** the endpoint-security serializer encodes an event envelope
- **WHEN** the encoded JSON is inspected
- **THEN** its `platform` field is `darwin`
