## ADDED Requirements

### Requirement: Operator actions commit their audit entry

The audit entry for an operator issuing a command or withdrawing one SHALL be committed in the same transaction as the command row it records, so an audit reader can never find a command issued to a host without an entry naming who issued it. Because the audit store belongs to another bounded context and cannot join that transaction, the entry SHALL be committed to an outbox and delivered to the audit store afterwards. Delivery MAY lag the action, SHALL be retried until it succeeds, and SHALL NOT drop an entry. Delivery SHALL NOT be carried out by the action's own request: the request SHALL commit its entry, ask for delivery, and answer, so that an audit store that is slow or unavailable delays the row rather than the response to an action that has already been carried out. An operator whose request for a destructive action times out cannot tell it from one that failed, and a retry issues it twice. Delivery SHALL also be attempted periodically and independently of any request, so that an entry whose request ended before it was delivered, or one written by another replica, is still delivered. An action that is refused or rolled back SHALL leave no entry. The delivered row SHALL carry the acting principal, the address the request came from, the affected host, the command's type and id, and the trace of the request that made it. The address MAY be absent from a row delivered by a replica running a version that predates the field, since such a replica reads the entry without it; the row itself SHALL still be delivered.

Issuing a command and withdrawing one SHALL be recorded as distinct actions, `command.issue` and `command.cancel`, because the two rows otherwise name the same host, command type and command id and nothing would distinguish a command that was sent from one that was taken back.

One operator action SHALL name one host throughout. The host a command is authorized against, the host it is stored against, and the host its audit entry names SHALL be the same identifier, so the authorization decision and the action it permitted can be correlated. The system SHALL therefore resolve the identifier at the request boundary, before authorizing, rather than letting each step normalize its own copy.

#### Scenario: An issued command commits its audit entry

- **GIVEN** an operator issuing a command to a host
- **WHEN** the command is queued
- **THEN** a `command.issue` entry has committed with it, naming the actor, the address they acted from, the host, and the command's type and id

#### Scenario: A withdrawn command is audited as a withdrawal

- **GIVEN** an operator withdrawing a command no agent has picked up
- **WHEN** the withdrawal commits
- **THEN** a `command.cancel` entry has committed with it, naming the same host, command type and command id as the issuance did

#### Scenario: One action names one host

- **GIVEN** a request issuing a command whose host id carries surrounding whitespace
- **WHEN** the command is queued
- **THEN** the authorization decision, the stored command and the committed audit entry all name the same host

#### Scenario: A refused action commits no audit entry

- **GIVEN** an issuance the service refuses, or a withdrawal of a command an agent has already acknowledged
- **WHEN** the action is refused
- **THEN** no audit entry is left in the outbox and no command row changed

#### Scenario: A slow audit store does not delay the action

- **GIVEN** an audit store that has not answered a delivery already in progress
- **WHEN** an operator issues a command
- **THEN** the command is queued, its entry is committed, and the request answers without waiting for the store
- **AND** the entry is delivered once the store answers

#### Scenario: An entry no request asked about is still delivered

- **GIVEN** an entry committed by a request that ended before it was delivered, or by another replica
- **WHEN** no request asks for a delivery
- **THEN** the periodic delivery records the row and clears the entry

#### Scenario: A delivery failure delays the audit row

- **GIVEN** an audit store that is unavailable when a command is issued
- **WHEN** the command is issued
- **THEN** the command is queued and its entry stays in the outbox
- **AND** a later delivery, once the store is available, records the row and clears the entry
