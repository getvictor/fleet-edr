# Extension application control: version-regression re-sync delta

## MODIFIED Requirements

### Requirement: Snapshot is the source of truth for decisions

The extension SHALL keep an in-memory snapshot of the active policy, indexed for constant-time lookup by `(rule_type, identifier)`. The snapshot SHALL also be persisted to a file under `/var/db/com.fleetdm.edr/application-control.json` so that the policy survives extension restarts. The in-memory and on-disk forms MUST be kept consistent: applying a new snapshot SHALL atomically update the in-memory copy and SHALL write the on-disk copy with a write-to-temporary-file-then-rename sequence so a crash mid-write cannot leave the file partially written.

Each snapshot carries two recency markers for the same `policy_id`: a `policy_version` that the server increments on every policy mutation (monotonic within a single server database lifetime) and a `policy_epoch`, the policy's server-assigned `updated_at` timestamp in Unix microseconds. The epoch SHALL survive a server database restore-from-backup or reset that regresses `policy_version`, because the operator's next mutation post-restore stamps the current wall-clock, which is strictly greater than any pre-restore epoch a host persisted.

The extension SHALL accept an incoming snapshot for the same `policy_id` when its `policy_version` is greater than the active snapshot's OR its `policy_epoch` is greater than the active snapshot's, and SHALL reject it (keep the active snapshot, perform no disk write) only when both are less than or equal to the active snapshot's. A snapshot whose `policy_epoch` is absent SHALL be treated as epoch `0`, so a server that does not yet emit the field falls back to version-only gating. Accepting on the epoch axis is what re-syncs a host after a server-side regression; rejecting when both axes are older is what preserves protection against duplicate and out-of-order replays.

#### Scenario: An incoming snapshot replaces the prior one atomically

- **GIVEN** the extension is already running with an applied snapshot at version `V`
- **WHEN** it receives a new snapshot at version `V+1`
- **THEN** the in-memory snapshot is the `V+1` snapshot immediately after acceptance
- **AND** the on-disk file reflects the same version
- **AND** no exec is evaluated against a partial snapshot during the swap

#### Scenario: Extension restart restores the last applied snapshot

- **GIVEN** the extension has previously applied a snapshot at version `V` to disk
- **WHEN** the extension restarts
- **THEN** the in-memory snapshot is the version `V` snapshot from disk

#### Scenario: A stale snapshot is rejected

- **GIVEN** the extension's current snapshot is at version `V` and epoch `E`
- **WHEN** a snapshot for the same policy is delivered whose version is `<= V` AND whose epoch is `<= E`
- **THEN** the extension keeps its current snapshot and performs no disk write

#### Scenario: A version regression with a newer epoch re-syncs instead of freezing

- **GIVEN** the extension's current snapshot is at version `V` and epoch `E` (for example `V=25` persisted before a server database restore)
- **WHEN** a snapshot for the same policy is delivered whose version is lower than `V` but whose epoch is greater than `E` (the post-restore mutation stamped a fresh `updated_at`)
- **THEN** the extension accepts the snapshot and the in-memory and on-disk forms reflect the delivered lower version
- **AND** the delivered ruleset enforces immediately rather than the host staying frozen on the stale ruleset

## ADDED Requirements

### Requirement: Application control re-sync event

When the extension accepts a snapshot for an already-applied `policy_id` whose `policy_version` regressed (is lower than the active snapshot's) but whose `policy_epoch` advanced, it SHALL treat this as an authoritative regression (the server-database-restore signature), log the acceptance at a level above `Info`, and emit an event of kind `application_control_resync`. The event SHALL carry `policy_id`, `previous_version`, `new_version`, `previous_epoch`, `new_epoch`, and `reason`. The event makes the regression operator-visible through the existing event channel rather than leaving it as a host-only log line. A normal forward apply (version advancing) SHALL NOT emit this event.

#### Scenario: A version regression emits a re-sync event

- **GIVEN** the extension's current snapshot is at version `25` and epoch `E`
- **WHEN** it accepts a snapshot for the same policy at version `2` whose epoch is greater than `E`
- **THEN** the extension emits an `application_control_resync` event whose `previous_version` is `25`, `new_version` is `2`, and `reason` records the regression
- **AND** the event is sent through the same channel as other extension events

#### Scenario: A normal forward apply emits no re-sync event

- **GIVEN** the extension's current snapshot is at version `V`
- **WHEN** it accepts a snapshot at version `V+1` whose epoch also advanced
- **THEN** the extension does NOT emit an `application_control_resync` event
