## ADDED Requirements

### Requirement: A forked process inherits its parent's signature

A fork-without-exec child runs its parent's image, so the system SHALL give it the parent's code-signing identity, its content hash and its code-directory hash, alongside the image path it already inherits. Leaving them empty while recording the path states that the process is running a binary for which nothing is known about its signature, which is not what the record shows: the parent's signature is known, and the child is running that same binary.

All of it SHALL be resolved by the same lookup, from the same generation and the same image within a re-exec chain, as the inherited path. Inheriting the path from one image and the identity from another would describe a process that never existed.

A parent carrying no identity SHALL yield none. Inheritance copies what the parent has, and where the parent's signature was never observed there is nothing to copy; asserting one would be an invention rather than an inheritance.

An exec on that PID SHALL replace the inherited identity with the exec'd image's, in the same write that replaces the path, so no inherited identity survives across an exec boundary.

An identity the record inherited SHALL remain distinguishable from one observed directly: a record that has never been imaged by an exec can only have inherited what it carries. A reader asking what signed a process is entitled to know which of the two answers it has, because they are different qualities of evidence even though both are correct.

Records written before this SHALL NOT be retrospectively given an identity. Resolving a historical row's parent at its own fork timestamp requires that parent to still be recorded, and retention prunes it, so the answer for an old row would be a guess in a field that is read as fact.

#### Scenario: A forked worker carries the daemon's signature

- **GIVEN** a signed process that forks a child which never execs
- **WHEN** the fork is applied
- **THEN** the child record carries the parent's code-signing identity, content hash and code-directory hash
- **AND** it carries the parent's image path, from that same image

#### Scenario: An exclusion for a tool covers its forked children

- **GIVEN** an exclusion naming the team that signed a tool, and a chain whose non-shell parent is a fork-only child of that tool
- **WHEN** the chain is evaluated
- **THEN** the chain is suppressed, as it is for a chain parented by an exec'd instance of the same tool
- **AND** an operator therefore sees one consistent behavior from the exclusion rather than suppression on some instances and alerts on others

#### Scenario: An exec replaces an inherited identity

- **GIVEN** a fork-only record carrying its parent's identity
- **WHEN** an exec event for that PID is applied
- **THEN** the record carries the exec'd image's identity, hash and code-directory hash
- **AND** a chain parented by that process is matched on the exec'd identity, never on the inherited one

#### Scenario: A fork from an unsigned parent inherits nothing

- **GIVEN** a parent whose record carries no code-signing identity
- **WHEN** it forks a child which never execs
- **THEN** the child record carries no identity either
- **AND** a signature exclusion does not suppress a chain parented by it
