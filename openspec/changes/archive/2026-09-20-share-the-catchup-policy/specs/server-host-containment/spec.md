## ADDED Requirements

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
