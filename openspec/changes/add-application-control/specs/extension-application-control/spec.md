# Extension Application Control Specification

## Purpose

This capability is the extension-side half of application control: the in-process decision engine that the
Endpoint Security system extension consults on every authorized exec, the snapshot of rules that engine reads
from, and the contract by which a denial becomes a structured event for the server's alert pipeline. It owns
how a Mach-O exec target is reduced to the five identifier values used by application control rules, the fixed
precedence order in which those identifiers are matched against the snapshot, the durability guarantees on the
snapshot file, and the rule-by-rule behaviors that make the macOS code-signing model meaningful (CDHash is
only matched under the Hardened Runtime; signing identifiers are prefixed; missing signing-info never blocks
the AUTH callback).

In this phase the only enforced action is `BLOCK`. The engine recognizes the columns reserved for follow-on
phases (`enforcement=DETECT`, `action=ALLOW`, `action=SILENT_BLOCK`, the policy-level `default_action=BLOCK`
for Lockdown) but does not change behavior on them; that wiring arrives in a follow-on change.

## Requirements

## ADDED Requirements

### Requirement: Snapshot is the source of truth for decisions

The extension SHALL keep an in-memory snapshot of the active policy, indexed for constant-time lookup by
`(rule_type, identifier)`. The snapshot SHALL also be persisted to a file under
`/var/db/com.fleetdm.edr/application-control.json` so that the policy survives extension restarts. The
in-memory and on-disk forms MUST be kept consistent: applying a new snapshot SHALL atomically update the
in-memory copy and SHALL write the on-disk copy with a write-to-temporary-file-then-rename sequence so a
crash mid-write cannot leave the file partially written.

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

- **GIVEN** the extension's current snapshot is at version `V`
- **WHEN** a snapshot at version `V` or lower is delivered
- **THEN** the extension keeps its current snapshot and reports the duplicate to the agent

### Requirement: Target identifier tuple for every exec

For every authorized exec the extension SHALL build a target identifier tuple consisting of `cdhash`,
`file_sha256`, `signing_id_prefixed`, `leaf_cert_sha256`, `team_id`. The tuple values SHALL be derived as
follows:

- `cdhash`: the value of `process.cdhash` on `es_process_t`, populated only if the process runs under
  Apple's Hardened Runtime. For non-hardened processes this field SHALL be absent.
- `file_sha256`: the SHA-256 of the executable file. The extension SHALL maintain a cache keyed by
  `(inode, mtime)` and SHALL NOT recompute when the cache hits. On a cache miss the value MAY be absent for
  the current exec; the cache SHALL be filled off the AUTH callback for subsequent execs.
- `signing_id_prefixed`: `<team_id>:<signing_id>` when both are present, or `platform:<signing_id>` when the
  binary is an Apple platform binary, or absent when no signing_id is present.
- `leaf_cert_sha256`: the SHA-256 of the leaf X.509 certificate in the signed code's signing chain. The
  extension SHALL maintain a cache keyed by `(inode, mtime)` and SHALL NOT block the AUTH callback on the
  fetch. On a cache miss the value MAY be absent for the current exec.
- `team_id`: the value of `process.team_id`, or absent if the binary is unsigned.

#### Scenario: A signed non-Apple binary yields a full tuple after the cache warms

- **GIVEN** the extension's caches contain entries for the binary under test
- **WHEN** the extension builds the target tuple for an exec of that binary
- **THEN** the tuple contains `file_sha256`, `signing_id_prefixed` shaped as `<team_id>:<signing_id>`,
  `leaf_cert_sha256`, and `team_id`
- **AND** `cdhash` is present if the binary uses the Hardened Runtime and absent otherwise

#### Scenario: A first exec with cold caches still produces a tuple but with some fields absent

- **GIVEN** the extension's `file_sha256` and `leaf_cert_sha256` caches are empty for the binary under test
- **WHEN** the extension builds the target tuple for the exec
- **THEN** the tuple contains at least `team_id` and `signing_id_prefixed` where present
- **AND** the missing values do not delay the AUTH callback

#### Scenario: A platform binary's signing identifier carries the platform prefix

- **GIVEN** an exec of `/usr/bin/curl` (signed as an Apple platform binary)
- **WHEN** the extension builds the target tuple
- **THEN** `signing_id_prefixed` is `platform:com.apple.curl`

### Requirement: Precedence walk

The extension SHALL walk the target tuple against the snapshot in this fixed precedence order, returning on
the first match: `CDHASH`, `BINARY`, `SIGNINGID`, `CERTIFICATE`, `TEAMID`, `PATH`. The extension SHALL skip
the type when its identifier is absent from the target tuple. The extension SHALL NOT consult later types
after the first match.

#### Scenario: A more-specific match wins over a less-specific one

- **GIVEN** the snapshot contains a `BINARY` rule for the exec target's `file_sha256` and a `TEAMID` rule
  for its team
- **WHEN** the extension walks precedence for the exec
- **THEN** the engine returns the `BINARY` rule
- **AND** the `TEAMID` rule is not consulted

#### Scenario: An absent tuple component is skipped

- **GIVEN** an unsigned exec target whose tuple has no `team_id`, `signing_id_prefixed`, or
  `leaf_cert_sha256`
- **WHEN** the extension walks precedence for the exec
- **THEN** the engine consults `CDHASH`, `BINARY`, and `PATH` only

### Requirement: CDHash rules only match hardened-runtime processes

The extension SHALL only consult `CDHASH` rules when the exec target's `cdhash` is populated, which by the
target-tuple rule above is true exclusively for processes running under Apple's Hardened Runtime. A `CDHASH`
rule whose identifier nominally targets a non-hardened binary SHALL silently no-op for that exec.

#### Scenario: A CDHash rule does not match a non-hardened binary

- **GIVEN** a `CDHASH` rule whose identifier equals the CDHash of a non-hardened binary
- **WHEN** the extension walks precedence for an exec of that binary
- **THEN** the `CDHASH` rule does not match
- **AND** the walk continues to lower-precedence types

### Requirement: AUTH_EXEC denial on BLOCK match

When the precedence walk returns a rule whose `action=BLOCK` and `enforcement=PROTECT`, the extension SHALL
deny the AUTH_EXEC request so the new image does not run. When the walk returns no match, or returns a rule
whose `enforcement` is anything other than `PROTECT`, the extension SHALL allow the AUTH_EXEC request to
proceed. The decision SHALL be reached within the AUTH_EXEC deadline; the extension MUST NOT block on
signing-info fetches to reach a decision.

#### Scenario: A BLOCK rule denies the exec

- **GIVEN** the precedence walk for an exec returns a `BLOCK` / `PROTECT` rule
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is a deny
- **AND** the new image does not run

#### Scenario: No matching rule allows the exec

- **GIVEN** the precedence walk for an exec returns no match
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is allow

### Requirement: Block event emission

Whenever the extension denies an AUTH_EXEC because of a `BLOCK` rule, it SHALL emit an event of kind
`application_control_block`. The event SHALL carry `policy_id`, `policy_version`, `rule_id`, `rule_type`,
`rule_identifier`, `matched_identifier`, `severity`, `custom_msg` (nullable), `custom_url` (nullable),
`process`, and `ancestry`. The `matched_identifier` SHALL be the actual value from the target tuple that
caused the match (for example, the CDHash that hit a `CDHASH` rule).

#### Scenario: A block emits a block event whose matched_identifier matches the rule type

- **GIVEN** a `TEAMID` rule for `EQHXZ8M8AV` matches an exec
- **WHEN** the extension denies and emits the block event
- **THEN** the event's `rule_type` is `TEAMID`
- **AND** the event's `matched_identifier` is `EQHXZ8M8AV`

### Requirement: Lazy signing-info fetch is non-blocking

The extension SHALL compute `file_sha256` and `leaf_cert_sha256` outside of the AUTH_EXEC callback whenever
the value is not already cached. When neither value is cached at decision time, the corresponding rule types
SHALL silently miss for that exec, and the resulting cache entry SHALL be available to subsequent execs of
the same `(inode, mtime)`. The extension MUST NOT call into Security framework lookups inside the AUTH_EXEC
callback.

#### Scenario: A cold cache yields a silent miss then a warm hit

- **GIVEN** the `leaf_cert_sha256` cache is empty for a binary under test
- **WHEN** the binary is executed for the first time
- **THEN** any `CERTIFICATE` rule that would have matched silently misses for that exec
- **AND** the cache is filled after the AUTH callback returns
- **WHEN** the same binary is executed a second time
- **THEN** the `CERTIFICATE` rule matches and the AUTH callback returns deny within the deadline

### Requirement: Snapshot persistence format is typed

The on-disk snapshot SHALL be a JSON object whose top-level fields are `policy_id`, `policy_version`, and a
`rules` map keyed by `rule_type` whose values are arrays of rule records carrying at least `identifier`,
`action`, `enforcement`, and optional `custom_msg`, `custom_url`, `severity`. The extension SHALL replace any
pre-existing snapshot file with a fresh, typed file on first apply; the legacy `policy.json` format from the
prior singleton blocklist is deleted by this change and no compatibility code SHALL be added.

#### Scenario: A first apply replaces any prior snapshot file

- **GIVEN** an extension that has a legacy `policy.json` on disk
- **WHEN** the extension receives its first `set_application_control` command
- **THEN** the typed snapshot file is written
- **AND** the legacy file is removed
