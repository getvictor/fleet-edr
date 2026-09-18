## ADDED Requirements

### Requirement: An operator contains or releases a host

The server SHALL expose `POST /api/hosts/{host_id}/containment` taking `contained` and a `reason`, authorized as `host.isolate` on that host, which for an interactive session requires a recent authentication. A request with a blank reason SHALL be refused with `reason_required`, a reason longer than 1024 characters with `reason_too_long`, and a request for a host with no active enrollment with `host_not_found`, changing nothing. A request that changes the host's containment SHALL record the new desired state (contained, reason, actor and time) at the host's next version, queue a `set_network_containment` command carrying that version, the state's epoch (the change time in microseconds, so ordering survives a database restore that sends versions backwards) and `contained`, audit the change as `host.contain` or `host.release` with the reason, version and epoch and, when the command was queued, its id, and return the state with the queued command's id. The state and its command SHALL be recorded together, under the host's lock, so the commands queued for a host are in the order of the states they carry: a change whose command cannot be queued SHALL record nothing and be refused, rather than leaving a state the catch-up has to notice. A request for the state the host already has SHALL change nothing, queue nothing and return the current state. A request MAY name `expected_version`, the version the caller read before asking: when it is present and the host's containment stands at any other version, the server SHALL refuse the change with `version_conflict`, storing nothing, queueing nothing and auditing nothing, and SHALL answer with the state the refusal was decided against, so the caller can decide again without reading a second time. That comparison SHALL be made under the same lock as the change, and before the request is judged a no-op, so that two changes naming one version cannot both be applied and a request made from a view the host has moved past is refused even when it asks for the state the host already holds. A request without `expected_version` SHALL ask for the state whatever the host currently holds. The generic `POST /api/commands` SHALL refuse `set_network_containment` and `isolate`, so containment changes only through this state.

#### Scenario: Commands are queued in the order of the states they carry

- **GIVEN** two changes to one host's containment made at the same moment
- **WHEN** each records its state and queues its command
- **THEN** the command carrying the later state is queued after the command carrying the earlier one

#### Scenario: A change whose command cannot be queued records nothing

- **GIVEN** an operator changing a host's containment
- **WHEN** the command carrying the new state cannot be queued
- **THEN** the request is refused, the host's state is unchanged, and nothing is audited

#### Scenario: An operator contains a host

- **GIVEN** an enrolled host that is not contained and an operator holding `host.isolate`
- **WHEN** the operator posts `contained` true with a reason
- **THEN** the host's state is contained at version 1 with that reason and actor
- **AND** a `set_network_containment` command carrying version 1, the state's epoch and `contained` true is queued for the host
- **AND** a `host.contain` audit event records the reason and version

#### Scenario: A release is recorded the same way

- **GIVEN** a contained host at version 1
- **WHEN** the operator posts `contained` false with a reason
- **THEN** the host's state is not contained at version 2, a command carrying version 2 and `contained` false is queued, and a `host.release` audit event records it

#### Scenario: A change without a reason is refused

- **WHEN** the operator posts a containment change with a blank reason
- **THEN** the server responds `reason_required` and changes nothing

#### Scenario: A reason over the limit is refused

- **WHEN** the operator posts a containment change whose reason is longer than 1024 characters
- **THEN** the server responds `reason_too_long` and changes nothing

#### Scenario: A host that is not enrolled cannot be contained

- **WHEN** the operator posts a containment change for a host with no active enrollment
- **THEN** the server responds `host_not_found` and changes nothing

#### Scenario: A change naming a version the host has moved past is refused

- **GIVEN** an operator who read a host's containment and then asks for a change naming that version
- **WHEN** another operator has changed the host in between
- **THEN** the request is refused as a conflict, the host keeps the other operator's state, and nothing is queued or audited
- **AND** the refusal carries the state it lost to, read under the same lock that refused it

#### Scenario: Asking for the current state changes nothing

- **GIVEN** a contained host
- **WHEN** the operator posts `contained` true again
- **THEN** the state keeps its version, no command is queued, no audit event is recorded, and the current state is returned

#### Scenario: Containment is not issued through the generic command endpoint

- **WHEN** an operator posts a `set_network_containment` or `isolate` command to `POST /api/commands`
- **THEN** the server refuses it as an unsupported command type

### Requirement: The containment state is readable

The server SHALL expose `GET /api/hosts/{host_id}/containment`, authorized as `host.read` on that host, returning the desired state (contained, version, epoch, reason, actor and updated time) and its delivery: the host's latest `set_network_containment` command with its id, status and result, and whether that command carries the current version and epoch. A host that has never had a containment state SHALL be returned not contained at version 0 with no delivery. `GET /api/containment`, authorized as `host.read`, SHALL return every host that has a containment state, released ones included, each with its delivery, so the host list can mark them.

#### Scenario: A contained host shows its state and delivery

- **GIVEN** a host contained at version 1 whose command is pending
- **WHEN** an operator holding `host.read` reads its containment
- **THEN** the response carries `contained` true, version 1, the reason and actor, and a delivery naming the command, its pending status, and that it carries the current state

#### Scenario: The host list shows every host with a state

- **GIVEN** one contained host and one host that was contained and then released
- **WHEN** an operator holding `host.read` lists containment
- **THEN** both hosts are returned with their state and delivery, and hosts never contained are not

#### Scenario: A host never contained has no state

- **WHEN** an operator reads the containment of a host that has never had one
- **THEN** the response carries `contained` false, version 0 and no delivery

### Requirement: Hosts converge on their containment state

The server SHALL, every five minutes, queue the current containment state again for each actively enrolled host that has one and whose latest `set_network_containment` command does not deliver it: there is none, it carries a different version or epoch, it expired or was cancelled, it failed at least six hours ago, or it was queued at or before the host's latest enrollment. A pending, acknowledged or completed command carrying the current state, or one that failed less than six hours ago, SHALL NOT be queued again, and a host that has never had a containment state SHALL receive nothing. The catch-up SHALL queue under the host's lock and against the state it holds then, so a state it read at the start of a sweep that has since changed queues nothing rather than a command carrying the older state.

#### Scenario: A concurrent change is not overtaken by the catch-up

- **GIVEN** a host whose containment state changed after the catch-up read it
- **WHEN** the catch-up comes to queue the state it read
- **THEN** it queues nothing, because the host no longer holds that state

#### Scenario: A host whose command expired is sent the state again

- **GIVEN** a contained host whose latest containment command expired undelivered
- **WHEN** the catch-up runs
- **THEN** a command carrying the current state is queued for the host

#### Scenario: A delivered state is not sent again

- **GIVEN** a contained host whose latest command carries the current state and completed
- **WHEN** the catch-up runs
- **THEN** nothing is queued for the host

#### Scenario: A host that re-enrolled is sent the state again

- **GIVEN** a contained host whose latest command was queued before the host last enrolled
- **WHEN** the catch-up runs
- **THEN** a command carrying the current state is queued for the host

#### Scenario: A failed delivery is retried after six hours

- **GIVEN** a contained host whose latest command failed
- **WHEN** the catch-up runs less than six hours after the failure, and again six hours after it
- **THEN** nothing is queued the first time, and the state is queued the second time
