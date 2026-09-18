## ADDED Requirements

### Requirement: A containment change commits its audit entry

The audit entry for a host being contained or released SHALL be committed in the same transaction as the change it records, so an audit reader can never find a host contained without an entry naming who contained it. Because the audit store belongs to another bounded context and cannot join that transaction, the entry SHALL be committed to an outbox and delivered to the audit store afterwards. Delivery MAY lag the change, SHALL be retried until it succeeds, and SHALL NOT drop an entry. Delivery SHALL NOT be carried out by the change's own request: the request SHALL commit its entry, ask for delivery, and answer, so that an audit store that is slow or unavailable delays the row rather than the response to a change that has already taken effect. An operator whose request to contain a host times out cannot tell it from one that failed, and a host left uncontained because its operator was waiting on an audit row is the outcome containment exists to prevent. Delivery SHALL also be attempted periodically and independently of any request, so that an entry whose request ended before it was delivered, or one written by another replica, is still delivered. A change that is refused or rolled back SHALL leave no entry. The delivered row SHALL carry the acting principal, the address the request came from, the reason, the state's version and epoch, the id of the command queued with the change, and the trace of the request that made it. The address MAY be absent from a row delivered by a replica running a version that predates the change which added it, since such a replica reads the entry without it; the row itself SHALL still be delivered.

#### Scenario: A change commits with its audit entry

- **GIVEN** an operator containing a host and later releasing it
- **WHEN** each change commits
- **THEN** its audit entry has committed with it, naming the actor, the host, the reason, the version and epoch, and the command the change queued

#### Scenario: A delivery failure delays the audit row

- **GIVEN** an audit store that is unavailable when a host is contained
- **WHEN** the host is contained
- **THEN** the change succeeds and its entry stays in the outbox
- **AND** a later delivery, once the store is available, records the row with the address the operator acted from and clears the entry

#### Scenario: A refused change leaves no audit entry

- **GIVEN** a change with no reason, a reason over the limit, a host that is not enrolled, a request for the state the host already has, or a change whose command cannot be queued
- **WHEN** the change is refused
- **THEN** no audit entry is left in the outbox

#### Scenario: The sweep delivers what a request left behind

- **GIVEN** an entry a containment change committed but whose request could not deliver
- **WHEN** the sweep next runs
- **THEN** the entry is delivered as an audit row and cleared
