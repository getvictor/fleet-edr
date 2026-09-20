## ADDED Requirements

### Requirement: Concurrent rule changes to one policy serialize

Rule mutations that touch the same policy SHALL serialize against one another rather than fail. Each one changes two things, the rule and the policy version that makes the change visible to hosts, and the system SHALL acquire them in one order for every mutation. Approaching the same two rows from opposite ends leaves each writer holding what the other needs, and the database resolves that by aborting one of them, which reaches the operator as a failed request for a change that was valid.

The order SHALL be the policy first. That is the row every rule mutation has in common, so locking it first is what makes the set of mutations a queue rather than a race; a create additionally takes a shared lock on that row as a consequence of the rule referencing it, and must therefore already hold the stronger one.

Serializing per policy SHALL NOT extend to different policies, which have no row in common and no reason to wait for each other.

A mutation naming a policy or a rule that does not exist SHALL be reported as not found, and SHALL be reported that way whether the absence is discovered while ordering the locks or afterwards. A database that cannot answer SHALL NOT be reported that way: an operator told their rule is gone believes someone else deleted it, which is a different event from a change that failed and can be retried.

#### Scenario: Concurrent rule creates do not deadlock

- **GIVEN** a policy
- **WHEN** several operators create rules in it at the same time
- **THEN** every create either succeeds or fails for its own reason
- **AND** none fails because the database aborted it to resolve a deadlock

#### Scenario: A single-rule change and a bulk upsert do not deadlock

- **GIVEN** a policy holding rules
- **WHEN** single-rule changes and a bulk upsert of the same policy run at the same time
- **THEN** each completes or fails on its own merits
- **AND** none fails because the database aborted it to resolve a deadlock

#### Scenario: A rule change waits for whoever holds the policy

- **GIVEN** a policy another writer is already holding
- **WHEN** an operator changes a rule in that policy
- **THEN** the change waits for the holder rather than proceeding beside it
- **AND** a wait that runs out is reported as a failed change, not as a missing rule

#### Scenario: A database that cannot answer is not a missing rule

- **GIVEN** a rule whose policy cannot be read because the database fails
- **WHEN** an operator changes that rule
- **THEN** the failure is reported as a failure
- **AND** not as the rule having been deleted
