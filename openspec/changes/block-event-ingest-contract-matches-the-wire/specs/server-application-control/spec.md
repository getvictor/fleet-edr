# Server Application Control Specification

## MODIFIED Requirements

### Requirement: Application control block event contract

The system SHALL accept ingest events of kind `application_control_block` from agents through the same host-token-authenticated `POST /api/events` channel that carries every other agent event. The system MUST bind every accepted event to the `host_id` resolved by the existing host-token middleware and MUST reject events whose envelope `host_id` does not match the authenticated host.

Each event MUST carry `pid`, `path`, `policy_id`, `policy_version`, `rule_id`, `rule_type`, `identifier`, and `severity`. The event MAY carry `custom_msg` and `custom_url`, which are absent rather than null when the matched rule does not set them. The `identifier` is the value from the target tuple that actually matched, not the rule's own stored identifier, so an operator reading the alert sees which of the process's identities was the one that hit.

The system SHALL accept events whose `policy_id` or `rule_id` does not correspond to a known rule (so an in-flight block is not lost when a rule is deleted after the block fired).

#### Scenario: A block event for an unknown rule is accepted

- **GIVEN** an agent posts an `application_control_block` event whose `rule_id` does not exist
- **WHEN** the server ingests the event
- **THEN** the server responds with HTTP 200 and the event is persisted

#### Scenario: A block event for a now-deleted rule is accepted

- **GIVEN** a rule that existed when the agent denied the exec but was deleted before the event reached the server
- **WHEN** the agent posts the `application_control_block` event
- **THEN** the server accepts and persists the event so the historical decision is not lost
