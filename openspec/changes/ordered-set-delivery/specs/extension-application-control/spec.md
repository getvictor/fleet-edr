# Extension application control delta

## MODIFIED Requirements

### Requirement: Snapshot is the source of truth for decisions

The extension SHALL keep an in-memory snapshot of the active policy, indexed for constant-time lookup by `(rule_type, identifier)`. The snapshot SHALL also be persisted to a file under `/var/db/com.fleetdm.edr/application-control.json` so that the policy survives extension restarts. The in-memory and on-disk forms MUST be kept consistent: applying a new snapshot SHALL atomically update the in-memory copy and SHALL write the on-disk copy with a write-to-temporary-file-then-rename sequence so a crash mid-write cannot leave the file partially written.

Each snapshot carries two recency markers for the same `policy_id`: a `policy_version` that the server increments on every policy mutation (monotonic within a single server database lifetime) and a `policy_epoch`, the policy's server-assigned `updated_at` timestamp in Unix microseconds. The server forces the epoch past its previous value on every mutation, so it orders every snapshot the server issues, and it survives a server database restore-from-backup or reset that regresses `policy_version`, because the operator's next mutation post-restore stamps a time later than any pre-restore epoch a host persisted.

The extension SHALL accept an incoming snapshot for the same `policy_id` only when it is ahead of the active snapshot, ordered by `policy_epoch` and then by `policy_version`, and SHALL otherwise reject it (keep the active snapshot, perform no disk write). A snapshot whose `policy_epoch` is absent SHALL be treated as epoch `0`, so a server that does not yet emit the field is ordered by version alone. Ordering by epoch first is what re-syncs a host after a server-side regression, and it also refuses a snapshot issued before a restore that reaches the host after one saved since, whose version is higher and whose epoch is older. The watched-path set is ordered by the same rule.

The change from the prior requirement is the ordering: a snapshot ahead on either axis was accepted, which applied that pre-restore snapshot and left it in force until the next mutation.

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

#### Scenario: A pre-restore snapshot is refused

- **GIVEN** the extension's current snapshot was saved after a server database restore, at a version lower than before the restore
- **WHEN** a snapshot issued before the restore is delivered for the same policy, with a higher version and an earlier epoch
- **THEN** the extension keeps its current snapshot and performs no disk write

#### Scenario: A version regression with a newer epoch re-syncs instead of freezing

- **GIVEN** the extension's current snapshot is at version `V` and epoch `E` (for example `V=25` persisted before a server database restore)
- **WHEN** a snapshot for the same policy is delivered whose version is lower than `V` but whose epoch is greater than `E` (the post-restore mutation stamped a fresh `updated_at`)
- **THEN** the extension accepts the snapshot and the in-memory and on-disk forms reflect the delivered lower version
- **AND** the delivered ruleset enforces immediately rather than the host staying frozen on the stale ruleset
