# server-host-containment Specification

## Purpose

Host containment is the EDR's server-side authority for cutting a compromised Mac off from the network and giving its access back. It owns the durable containment state of each host and the version and epoch that order changes to it, the operator surface for containing and releasing with a reason, the set of destinations a contained host may still reach, the commands that carry that state to hosts and the convergence rules that keep an offline or re-enrolling host on the state it is owed, the readable state the console and the host list report, and the audit entry that records who made each change, committed with the change rather than after it.

The governing constraint is that a host is owed exactly one state by one rule, so an operator, a re-enrollment, and a retry cannot disagree about whether a Mac is contained.

## Requirements

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

### Requirement: Operators choose what a contained host can still reach

Containment ships a fixed lifeline: a contained host keeps loopback, DHCP, resolution of the server name, and its connection to the EDR server, and nothing else. An incident responder often needs a few more destinations to stay reachable, such as an MDM or remediation server, a forensic collection share, or a VPN concentrator, and without them containment cuts off the responder's own tooling along with the intruder's. The system SHALL therefore keep a deployment-wide set of addresses a contained host may still reach, and SHALL let an operator read and replace it.

The set SHALL be deployment-wide rather than per host, and SHALL be versioned as a whole. A version names exactly one list, so a host either holds that version or does not; per-entry versions would let a host hold half a set, which is a state no reader could describe. The set SHALL be replaced whole rather than amended, because a caller sending only what it wants added could not express a removal. A deployment SHALL start with an empty set, which is the lifeline every contained host already has.

An entry SHALL name a destination as an IP address or a CIDR range, and MAY narrow it to a single port, to TCP or UDP, or to both. An entry MAY carry an operator's note, so the console and the audit trail can say "MDM server" rather than an address. A destination SHALL be stored canonically: a bare address is stored as its single-address prefix and a range is stored masked, so one destination has one spelling and two spellings of it cannot be stored as two entries.

The system SHALL refuse an entry that would leave containment meaningless, and SHALL refuse the whole replacement rather than storing the entries around it, because a responder who asked for four destinations and silently got three would discover it during an incident. Refusing only the default routes would be insufficient, since two half-sized ranges cover the same space, so the refusal SHALL be expressed as a floor on how broad any single range may be, set where a legitimate operator range still fits. The system SHALL also refuse a destination listed twice, a port outside the valid range, a transport it cannot express as a filter rule, and a set larger than a fixed cap. Each refusal SHALL identify which entry was refused, so an operator editing a long set is told what to fix.

Replacing the set SHALL require a reason, and SHALL be audited with it, as containing a host is. The audit record SHALL carry the acting principal, the reason, the new version, which destinations the replacement added and removed, and which destinations kept their place but were renamed, because a set that gained one destination is otherwise indistinguishable from the same set saved again, and a renamed one from an untouched one. Each destination in that record SHALL be carried as its own fields rather than as rendered text, because an operator's own label for a destination is part of it: rendered into a sentence, a label could be written to make one change read as another in the record of who widened containment.

Replacing the set SHALL be a distinct permission from containing a host, held by fewer roles than containment itself, and SHALL require a recently authenticated interactive session. An operator containing a host decides about that host; an operator editing this set decides what every contained host, present and future, can still talk to, which is the one edit that weakens a containment already in force.

A replacement MAY name the version the operator read before editing. When it does and the stored set has moved on since, the system SHALL refuse the replacement and SHALL store nothing, so an operator is told rather than silently overwriting an edit they never saw. A replacement that names no version SHALL be applied to whatever the set currently holds, which is what a scripted caller asks for.

The set SHALL be delivered to a contained host with its containment state, on the same command, rather than on a command of its own. A host SHALL be considered to hold the current state only when its latest command carries BOTH that state and the set in force, so a change to the set alone makes every contained host's latest command stale and the catch-up that already re-queues a missed containment re-queues it. This is what lets an operator widen what contained hosts may reach without releasing and re-containing each of them. Delivery MAY lag a change by up to one catch-up interval; a change an operator makes while containing a host SHALL be carried by that host's own command immediately.

A command that releases a host SHALL carry neither the addresses nor the set's version, because a released host restricts nothing for an allowance to qualify. A released host's command SHALL likewise be judged without the set: a host that is not contained would otherwise look stale to the catch-up the moment an operator edited the set, and every host ever contained would be handed a release it already has.

The endpoint SHALL enforce the set as part of the lifeline it already enforces, allowing each destination outbound on the port and transport the entry names, and both transports for an entry naming none. An entry the endpoint cannot express SHALL be dropped rather than refusing the containment: the set was validated before it was stored, so a drop means the two disagree, and a host contained with one allowance missing is a better outcome than a host not contained at all. The endpoint SHALL treat a containment carrying a different set as a lifeline that moved, even though the containment state itself is unchanged, or a change to the set would be accepted and discarded while the command reported success.

#### Scenario: The set starts empty and is replaced whole

- **GIVEN** a deployment whose reachable-address set has never been edited
- **WHEN** an operator reads it, replaces it with two destinations, and then replaces it with only one of them
- **THEN** the first read reports an empty set at the version a host needs no telling about
- **AND** each replacement stores the set at the next version, canonically, in the order written
- **AND** the destination left out of the second replacement is gone rather than merged with it

#### Scenario: An address that would undo containment is refused

- **GIVEN** an operator replacing the set
- **WHEN** the set contains a range broader than the floor for its address family, an address that is not an address, a port outside the valid range, a transport the system cannot express, a note over the cap, a destination listed twice, or more entries than the cap allows
- **THEN** the replacement is refused, naming the entry at fault
- **AND** the stored set is left exactly as it was, including any valid entries in the refused replacement

#### Scenario: Widening the set is audited with its reason

- **GIVEN** an operator replacing the set with a different destination
- **WHEN** the replacement is stored
- **THEN** an audit record names the acting principal, the reason, the new version, and the destinations added, removed and renamed, each as its own fields
- **AND** a destination whose label alone changed is recorded as renamed rather than as one leaving and another arriving
- **AND** a replacement with no reason is refused and stores nothing

#### Scenario: Editing the set is its own permission

- **GIVEN** a caller lacking the permission for the operation it asks for, reading or replacing
- **WHEN** the caller makes that request
- **THEN** the request is refused before its body is read
- **AND** the two operations are gated on separate permissions, so a caller holding only the read permission can read the set and cannot replace it

#### Scenario: Two operators editing at once are told

- **GIVEN** two operators who have both read the set at the same version
- **WHEN** the first stores a replacement and the second then stores one naming the version they read
- **THEN** the second replacement is refused and stores nothing
- **AND** the first operator's set is what the deployment holds

#### Scenario: A set change reaches a host that is already contained

- **GIVEN** a contained host whose latest command carries the set in force
- **WHEN** an operator replaces the set, leaving that host's containment state untouched
- **THEN** the host's latest command stops counting as current and the catch-up queues it the state again with the new set
- **AND** the new command carries the set's version and its addresses
- **AND** a further sweep queues nothing once the host holds them

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

### Requirement: A host is owed a state by one rule

The decision that a host should be sent a pushed state again SHALL be the same wherever the system pushes one, so that a change to delivery or retry semantics cannot apply to one pushed state and not another. A host SHALL be sent the state again when it has never been sent one, when its latest command carries a different state, when that command was queued at or before the host's latest enrollment, and when that command expired or was cancelled. A command that failed SHALL be retried only once a bounded period has passed since it failed, and a failure with no recorded completion time SHALL NOT be retried early. A command that is pending, acknowledged or completed SHALL NOT cause the state to be sent again.

A command whose status the running version does not recognize SHALL be left alone rather than treated as undelivered, since such a status was written by a newer version and resending against it would put replicas mid-upgrade in conflict. Each pushed state's own command status SHALL therefore be mapped onto the shared vocabulary explicitly, so that a status which stopped being recognized is a build or test failure rather than a fleet that silently stops being caught up.

#### Scenario: A host that never received the state is sent it

- **GIVEN** a host with no command of the type, or whose latest one carries a different state
- **WHEN** the catch-up runs
- **THEN** the state is queued for it

#### Scenario: A host that reinstalled is sent the state again

- **GIVEN** a host whose latest command was queued at or before its most recent enrollment
- **WHEN** the catch-up runs
- **THEN** the state is queued for it, because the reinstall removed the copy the command delivered

#### Scenario: A command in flight is left alone

- **GIVEN** a host whose latest command carries the current state and is pending, acknowledged or completed
- **WHEN** the catch-up runs
- **THEN** nothing is queued for it

#### Scenario: A failed command is retried only after a bounded wait

- **GIVEN** a host whose latest command failed
- **WHEN** the catch-up runs before the wait has passed, and again after it
- **THEN** nothing is queued the first time and the state is queued the second

#### Scenario: A status the version does not recognize is left alone

- **GIVEN** a host whose latest command carries a status this version does not know
- **WHEN** the catch-up runs
- **THEN** nothing is queued for it
