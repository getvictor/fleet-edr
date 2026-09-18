## ADDED Requirements

### Requirement: Operators choose what a contained host can still reach

Containment ships a fixed lifeline: a contained host keeps loopback, DHCP, resolution of the server name, and its connection to the EDR server, and nothing else. An incident responder often needs a few more destinations to stay reachable, such as an MDM or remediation server, a forensic collection share, or a VPN concentrator, and without them containment cuts off the responder's own tooling along with the intruder's. The system SHALL therefore keep a deployment-wide set of addresses a contained host may still reach, and SHALL let an operator read and replace it.

The set SHALL be deployment-wide rather than per host, and SHALL be versioned as a whole. A version names exactly one list, so a host either holds that version or does not; per-entry versions would let a host hold half a set, which is a state no reader could describe. The set SHALL be replaced whole rather than amended, because a caller sending only what it wants added could not express a removal. A deployment SHALL start with an empty set, which is the lifeline every contained host already has.

An entry SHALL name a destination as an IP address or a CIDR range, and MAY narrow it to a single port, to TCP or UDP, or to both. An entry MAY carry an operator's note, so the console and the audit trail can say "MDM server" rather than an address. A destination SHALL be stored canonically: a bare address is stored as its single-address prefix and a range is stored masked, so one destination has one spelling and two spellings of it cannot be stored as two entries.

The system SHALL refuse an entry that would leave containment meaningless, and SHALL refuse the whole replacement rather than storing the entries around it, because a responder who asked for four destinations and silently got three would discover it during an incident. Refusing only the default routes would be insufficient, since two half-sized ranges cover the same space, so the refusal SHALL be expressed as a floor on how broad any single range may be, set where a legitimate operator range still fits. The system SHALL also refuse a destination listed twice, a port outside the valid range, a transport it cannot express as a filter rule, and a set larger than a fixed cap. Each refusal SHALL identify which entry was refused, so an operator editing a long set is told what to fix.

Replacing the set SHALL require a reason, and SHALL be audited with it, as containing a host is. The audit record SHALL carry the acting principal, the reason, the new version, and which destinations the replacement added and removed, because a set that gained one destination is otherwise indistinguishable from the same set saved again.

Replacing the set SHALL be a distinct permission from containing a host, held by fewer roles than containment itself, and SHALL require a recently authenticated interactive session. An operator containing a host decides about that host; an operator editing this set decides what every contained host, present and future, can still talk to, which is the one edit that weakens a containment already in force.

A replacement MAY name the version the operator read before editing. When it does and the stored set has moved on since, the system SHALL refuse the replacement and SHALL store nothing, so an operator is told rather than silently overwriting an edit they never saw. A replacement that names no version SHALL be applied to whatever the set currently holds, which is what a scripted caller asks for.

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
- **THEN** an audit record names the acting principal, the reason, the new version, and the destinations added and removed
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
