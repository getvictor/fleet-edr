# Extension Application Control Specification

## Purpose

This capability is the extension-side half of application control: the in-process decision engine the Endpoint Security system extension consults on every authorized exec, the snapshot of rules that engine reads from, and the contract by which a denial becomes a structured event for the server's alert pipeline. It owns how a Mach-O exec target is reduced to the identifier values used by application control rules, the fixed precedence order in which those identifiers are matched against the snapshot, the durability guarantees on the snapshot file, the deadline-guarded synchronous SHA-256 the BINARY layer depends on, the operator-selectable fail-open / fail-closed / audit-only posture when that hash cannot complete in time, the unconditional Apple platform-binary carve-out that runs before the snapshot walk, and the rule-by-rule behaviors that make the macOS code-signing model meaningful (CDHash is only matched under the Hardened Runtime; signing identifiers are prefixed; leaf-cert lookups never block the AUTH callback).

The only enforced action is `BLOCK` under `enforcement=PROTECT`. The engine recognizes the columns reserved for follow-on phases (`enforcement=DETECT`, `action=ALLOW`, `action=SILENT_BLOCK`) but does not change exec behavior on them: a matched rule whose enforcement is anything other than `PROTECT` is treated as "matched but does not deny" and the exec is allowed. The detect-mode closed loop (`application_control_would_block` events, the per-decision `decision` field on the regular exec event) is deferred and is NOT part of the shipped behavior this live spec describes.

## Requirements

### Requirement: Snapshot is the source of truth for decisions

The extension SHALL keep an in-memory snapshot of the active policy, indexed for constant-time lookup by `(rule_type, identifier)`. The snapshot SHALL also be persisted to a file under `/var/db/com.fleetdm.edr/application-control.json` so that the policy survives extension restarts. The in-memory and on-disk forms MUST be kept consistent: applying a new snapshot SHALL atomically update the in-memory copy and SHALL write the on-disk copy with a write-to-temporary-file-then-rename sequence so a crash mid-write cannot leave the file partially written.

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

For every authorized exec the extension SHALL build a target identifier tuple consisting of `cdhash`, `signing_id_prefixed`, `leaf_cert_sha256`, `team_id`, and `path`. `file_sha256` is no longer part of the tuple struct itself; it is supplied as a separate `HashOutcome` at decide time so the hash compute can run on the AUTH callback thread under a deadline budget (see the deadline-guarded BINARY hash requirement below). The remaining tuple values SHALL be derived as follows:

- `cdhash`: the value of `process.cdhash` on `es_process_t`, populated only if the process runs under Apple's Hardened Runtime. For non-hardened processes this field SHALL be absent. (Note: this gate is ours; Santa applies CDHASH rules regardless of the Hardened Runtime flag. We gate because the kernel maps pages lazily on non-hardened processes and does not re-verify them post-load, so the CDHash ESF reports at exec is not a reliable identity for the bytes that will eventually execute.)
- `signing_id_prefixed`: `<team_id>:<signing_id>` when both are present, or `platform:<signing_id>` when the binary is an Apple platform binary, or absent when no signing_id is present.
- `leaf_cert_sha256`: the SHA-256 of the leaf X.509 certificate in the signed code's signing chain. The extension SHALL maintain a cache keyed by `(inode, mtime)` and SHALL NOT block the AUTH callback on the fetch. On a cache miss the value MAY be absent for the current exec.
- `team_id`: the value of `process.team_id`, or absent if the binary is unsigned.
- `path`: the canonical absolute filesystem path of the authorized exec target. Always present (the AUTH event carries it directly); the macOS canonicalization of `/tmp`, `/var`, and `/etc` into their `/private/...` forms is applied before matching so the precedence walk compares against the same canonical form the server validates and persists rule identifiers in.

#### Scenario: A signing-id rule matches a signed non-Apple binary by its prefixed signing identity

- **GIVEN** the snapshot contains a `SIGNINGID` block rule whose identifier is `<team_id>:<signing_id>`
- **AND** the exec target is a signed non-Apple binary whose tuple carries that same `<team_id>:<signing_id>` signing identity
- **WHEN** the extension walks precedence for the exec
- **THEN** the `SIGNINGID` rule matches and the exec is denied
- **AND** the matched identifier is the `<team_id>:<signing_id>` value

#### Scenario: A cold leaf-cert lookup yields an absent value without blocking

- **GIVEN** the extension's `leaf_cert_sha256` cache has no entry for an exec target whose leaf certificate cannot be resolved (unsigned, ad-hoc-signed, or an unreadable path)
- **WHEN** the extension looks up the target's leaf certificate SHA-256
- **THEN** the lookup returns an absent value rather than blocking on a Security-framework call
- **AND** any `CERTIFICATE` rule that would have matched silently misses for that exec

#### Scenario: A signing-id rule matches a platform binary by its platform-prefixed signing identity

- **GIVEN** the snapshot contains a `SIGNINGID` block rule whose identifier is `platform:<signing_id>`
- **AND** the exec target is a kernel-classified Apple platform binary whose tuple carries that same `platform:<signing_id>` signing identity
- **WHEN** the extension walks precedence for the exec
- **THEN** the `SIGNINGID` rule matches on the platform-prefixed identity and the matched identifier is the `platform:<signing_id>` value

### Requirement: Precedence walk

The extension SHALL walk the target tuple against the snapshot in this fixed precedence order, returning on the first match: `CDHASH`, `BINARY`, `CERTIFICATE`, `SIGNINGID`, `TEAMID`, `PATH`. The extension SHALL skip the type when its identifier is absent from the target tuple. The extension SHALL NOT consult later types after the first match.

#### Scenario: A more-specific match wins over a less-specific one

- **GIVEN** the snapshot contains a `CDHASH` rule for the exec target's cdhash and a `SIGNINGID` rule for its signing identifier
- **WHEN** the extension walks precedence for the exec
- **THEN** the engine returns the `CDHASH` rule
- **AND** the `SIGNINGID` rule is not consulted

#### Scenario: An absent tuple component is skipped

- **GIVEN** an unsigned exec target whose tuple has no `team_id`, `signing_id_prefixed`, or `leaf_cert_sha256`
- **WHEN** the extension walks precedence for the exec
- **THEN** the engine consults `CDHASH`, `BINARY`, and `PATH` only

### Requirement: CDHash rules only match hardened-runtime processes

The extension SHALL only consult `CDHASH` rules when the exec target's `cdhash` is populated, which by the target-tuple rule above is true exclusively for processes running under Apple's Hardened Runtime. A `CDHASH` rule whose identifier nominally targets a non-hardened binary SHALL silently no-op for that exec.

#### Scenario: A CDHash rule does not match a non-hardened binary

- **GIVEN** a `CDHASH` rule whose identifier equals the CDHash of a non-hardened binary
- **WHEN** the extension walks precedence for an exec of that binary
- **THEN** the `CDHASH` rule does not match
- **AND** the walk continues to lower-precedence types

### Requirement: AUTH_EXEC denial on BLOCK match

When the precedence walk returns a rule whose `action=BLOCK` and `enforcement=PROTECT`, the extension SHALL deny the AUTH_EXEC request so the new image does not run. When the walk returns no match, or returns a rule whose `enforcement` is anything other than `PROTECT`, the extension SHALL allow the AUTH_EXEC request to proceed. The decision SHALL be reached within the AUTH_EXEC deadline. The extension MAY block the AUTH callback on a synchronous BINARY-rule SHA-256 compute bounded by the deadline budget (see the deadline-guarded BINARY hash requirement). The extension MUST NOT block the AUTH callback on `leaf_cert_sha256` fetches; those remain a lazy cache fill.

#### Scenario: A BLOCK rule denies the exec

- **GIVEN** the precedence walk for an exec returns a `BLOCK` / `PROTECT` rule
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is a deny
- **AND** the new image does not run

#### Scenario: No matching rule allows the exec

- **GIVEN** the precedence walk for an exec returns no match
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is allow

#### Scenario: A cold-cache exec on a CERTIFICATE-only target is allowed

- **GIVEN** the snapshot contains only a `CERTIFICATE` rule for an exec target
- **AND** the leaf certificate SHA-256 for that target is not yet cached
- **WHEN** the AUTH_EXEC callback runs
- **THEN** the `CERTIFICATE` rule silently misses for this exec
- **AND** the system allows the exec
- **AND** the cache is filled for subsequent execs

### Requirement: Block event emission

Whenever the extension denies an AUTH_EXEC because of a `BLOCK` rule, it SHALL emit an event of kind `application_control_block`. The event SHALL carry `policy_id`, `policy_version`, `rule_id`, `rule_type`, `rule_identifier`, `matched_identifier`, `severity`, `custom_msg` (nullable), `custom_url` (nullable), `process`, and `ancestry`. The `matched_identifier` SHALL be the actual value from the target tuple that caused the match (for example, the CDHash that hit a `CDHASH` rule).

#### Scenario: A block emits a block event whose matched_identifier matches the rule type

- **GIVEN** a `TEAMID` rule for `EQHXZ8M8AV` matches an exec
- **WHEN** the extension denies and emits the block event
- **THEN** the event's `rule_type` is `TEAMID`
- **AND** the event's `matched_identifier` is `EQHXZ8M8AV`

### Requirement: Lazy signing-info fetch is non-blocking

The extension SHALL compute `leaf_cert_sha256` outside of the AUTH_EXEC callback whenever the value is not already cached. When the value is not cached at decision time, the `CERTIFICATE` rule type SHALL silently miss for that exec, and the resulting cache entry SHALL be available to subsequent execs of the same `(inode, mtime)`. The extension MUST NOT call into Security framework lookups inside the AUTH_EXEC callback.

#### Scenario: A cold CERTIFICATE cache yields a silent miss then a warm hit

- **GIVEN** the `leaf_cert_sha256` cache is empty for a binary under test
- **WHEN** the binary is executed for the first time
- **THEN** any `CERTIFICATE` rule that would have matched silently misses for that exec
- **AND** the cache is filled after the AUTH callback returns
- **WHEN** the same binary is executed a second time
- **THEN** the `CERTIFICATE` rule matches and the AUTH callback returns deny within the deadline

### Requirement: Snapshot persistence format is typed

The on-disk snapshot SHALL be a JSON object whose top-level fields are `policy_id`, `policy_version`, and a `rules` map keyed by `rule_type` whose values are arrays of rule records carrying at least `identifier`, `action`, `enforcement`, and optional `custom_msg`, `custom_url`, `severity`. The extension SHALL replace any pre-existing snapshot file with a fresh, typed file on first apply; the legacy `policy.json` format from the prior singleton blocklist is deleted by this change and no compatibility code SHALL be added.

#### Scenario: A first apply replaces any prior snapshot file

- **GIVEN** an extension that has a legacy `policy.json` on disk
- **WHEN** the extension receives its first `set_application_control` command
- **THEN** the typed snapshot file is written
- **AND** the legacy file is removed

### Requirement: Platform-binary carve-out precedes the snapshot walk

Before consulting the active snapshot, the extension SHALL ALLOW any AUTH_EXEC whose target carries the kernel's `is_platform_binary` flag, and SHALL pin the result into the kernel's per-`(dev, inode, mtime)` AUTH cache by responding with `cache: true`. The carve-out SHALL run BEFORE the existing self-allow failsafe and BEFORE the precedence walk. The kernel's `is_platform_binary` flag is more conservative than any hand-curated path or signing-id allowlist would be: it is the kernel's own classification of "this binary is on the Apple-signed system image" and identifies launchd, xpcproxy, fseventsd, kextd, sysextd, systemextensionsd, WindowServer, loginwindow, mds, and every other Apple system binary without operator-maintained lists.

#### Scenario: An Apple platform binary is unconditionally allowed

- **GIVEN** the active snapshot contains a `BINARY` block rule whose identifier is the SHA-256 of `/sbin/launchd`
- **WHEN** the kernel issues an AUTH_EXEC for `/sbin/launchd` and reports `target.is_platform_binary == true`
- **THEN** the extension responds with `ES_AUTH_RESULT_ALLOW` and `cache: true`
- **AND** the precedence walk is NOT consulted
- **AND** the snapshot's `BINARY` rule does NOT cause a DENY

#### Scenario: A non-platform binary still walks the snapshot

- **GIVEN** the active snapshot contains a `BINARY` block rule for a non-Apple binary
- **WHEN** the kernel issues an AUTH_EXEC whose `target.is_platform_binary == false`
- **THEN** the platform-binary carve-out does not fire
- **AND** the extension proceeds to the self-allow failsafe and then the precedence walk

### Requirement: Deadline-guarded synchronous SHA-256 for BINARY rule consultation

The extension SHALL compute the exec target's SHA-256 synchronously on the AUTH_EXEC callback thread when the active snapshot contains at least one `BINARY` rule, bounded by a budget derived from the kernel-supplied `es_message_t.deadline`. The budget SHALL reserve a safety margin (target: 500 ms) for the post-hash work (snapshot lookup, kernel respond, optional event / notification dispatch) plus an unlucky page-in stall. The hash SHALL stream the file in chunks (target: 64 KiB) so the deadline budget is checked between chunks and an abort yields the kernel-respond path enough headroom to complete. When the active snapshot has zero `BINARY` rules, the extension SHALL skip the hash compute entirely (the result no rule could consult is wasted work).

The TOCTOU re-stat guard from the warm-cache compute path SHALL apply: if `fstat(2)` on the opened file descriptor reports a `(dev, inode, mtime)` tuple different from what the AUTH event delivered, the extension SHALL treat the outcome as unavailable (the file was atomically replaced between AUTH and read) and SHALL NOT poison the cache with a hash of the wrong file.

#### Scenario: Sync hash on cold cache decides the first exec

- **GIVEN** the active snapshot contains a `BINARY` block rule whose identifier is the SHA-256 of a binary the extension has never seen before (cache cold)
- **WHEN** the kernel issues an AUTH_EXEC for that binary
- **THEN** the extension computes the SHA-256 synchronously within the kernel deadline budget
- **AND** the precedence walk's BINARY layer matches the rule
- **AND** the extension responds with `ES_AUTH_RESULT_DENY`
- **AND** an `application_control_block` event is emitted

#### Scenario: Mutated `(dev, inode, mtime)` does not bypass the BINARY rule

- **GIVEN** the active snapshot contains a `BINARY` block rule for a binary whose mtime is mutated on every exec (an attacker invalidating the cache key to keep the first-exec ALLOW path open)
- **WHEN** each AUTH_EXEC arrives with a fresh `(dev, inode, mtime)` tuple
- **THEN** the extension re-computes the SHA-256 synchronously for every exec
- **AND** every exec hits the BINARY rule and is DENIED
- **AND** no exec slips past the rule on the first try

#### Scenario: Empty BINARY map skips the hash compute

- **GIVEN** the active snapshot has zero `BINARY` rules but at least one `SIGNINGID` rule
- **WHEN** the kernel issues an AUTH_EXEC
- **THEN** the extension does NOT call the deadline-bounded SHA-256 helper
- **AND** the precedence walk still consults CDHASH / SIGNINGID / TEAMID
- **AND** the AUTH callback latency does not include hash compute time

### Requirement: Deadline fallback posture

The active snapshot SHALL carry a `deadline_fallback` field whose value is one of `fail-closed`, `fail-open`, or `audit-only`. When the deadline-bounded SHA-256 cannot complete (the budget is exhausted between chunks) or returns a read failure (TOCTOU mismatch, missing file, fstat error), the extension SHALL apply the posture as the terminal verdict for the AUTH_EXEC, without continuing the precedence walk to `SIGNINGID` or `TEAMID` once every lower-precedence layer has been consulted and produced no match (a definitive lower-precedence DENY still dominates the BINARY layer's "could-have-fired" uncertainty).

- `fail-closed`: respond `ES_AUTH_RESULT_DENY`. Emit an `application_control_undecided` event with `verdict=deny` so the operator can audit the rate.
- `fail-open`: respond `ES_AUTH_RESULT_ALLOW`. Emit no event (the operator opted out of visibility).
- `audit-only`: respond `ES_AUTH_RESULT_ALLOW`. Emit an `application_control_undecided` event with `verdict=allow` so the operator can measure the cold-cache rate without changing exec behaviour.

When the snapshot payload omits the field, the extension SHALL substitute `fail-closed` (the documented v0.1.0 default; the only posture that closes the cold-cache window without operator awareness of the trade-off).

#### Scenario: fail-closed under deadline exceedance

- **GIVEN** the active snapshot carries `deadline_fallback=fail-closed` and at least one `BINARY` rule
- **WHEN** the AUTH_EXEC's deadline budget is exhausted before the SHA-256 stream completes
- **THEN** the extension responds `ES_AUTH_RESULT_DENY`
- **AND** emits an `application_control_undecided` event with `verdict=deny` and `reason=deadline`

#### Scenario: audit-only under deadline exceedance

- **GIVEN** the active snapshot carries `deadline_fallback=audit-only` and at least one `BINARY` rule
- **WHEN** the AUTH_EXEC's deadline budget is exhausted before the SHA-256 stream completes
- **THEN** the extension responds `ES_AUTH_RESULT_ALLOW`
- **AND** emits an `application_control_undecided` event with `verdict=allow` and `reason=deadline`

#### Scenario: fail-open under deadline exceedance

- **GIVEN** the active snapshot carries `deadline_fallback=fail-open` and at least one `BINARY` rule
- **WHEN** the AUTH_EXEC's deadline budget is exhausted before the SHA-256 stream completes
- **THEN** the extension responds `ES_AUTH_RESULT_ALLOW`
- **AND** no `application_control_undecided` event is emitted

#### Scenario: Missing deadline_fallback substitutes fail-closed

- **GIVEN** the agent delivers a snapshot payload that omits the `deadline_fallback` field
- **WHEN** the extension decodes the payload
- **THEN** the in-memory snapshot reports `deadline_fallback == fail-closed`
- **AND** subsequent deadline-exceeded AUTH_EXECs DENY per the fail-closed posture

### Requirement: Application Control undecided event

The extension SHALL emit an event of kind `application_control_undecided` only when the BINARY layer's hash outcome is unavailable AND the active snapshot's `deadline_fallback` is `fail-closed` or `audit-only`. The event SHALL carry `pid`, `path`, `verdict` (`allow` for audit-only, `deny` for fail-closed), `reason` (`deadline` when the budget was exhausted, `read_failed` when the file was unreadable or the TOCTOU re-stat failed), `file_size_bytes`, `policy_id`, and `policy_version`. The event SHALL be emitted AFTER the kernel `es_respond_auth_result` call so the post-respond cost does not eat into the deadline.

#### Scenario: read_failed reason on TOCTOU mismatch under fail-closed

- **GIVEN** the active snapshot carries `deadline_fallback=fail-closed` and at least one `BINARY` rule
- **WHEN** the AUTH_EXEC arrives but a `(dev, inode, mtime)` TOCTOU re-stat at hash-open time shows the file was replaced
- **THEN** the extension responds `ES_AUTH_RESULT_DENY`
- **AND** emits an `application_control_undecided` event with `verdict=deny` and `reason=read_failed`
