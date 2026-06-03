# Extension Application Control v0.1.0 AUTH_EXEC hardening

## ADDED Requirements

### Requirement: Platform-binary carve-out precedes the snapshot walk

Before consulting the active snapshot, the extension SHALL ALLOW any AUTH_EXEC whose target carries the kernel's
`is_platform_binary` flag, and SHALL pin the result into the kernel's per-`(dev, inode, mtime)` AUTH cache by
responding with `cache: true`. The carve-out SHALL run BEFORE the existing self-allow failsafe and BEFORE the
precedence walk. The kernel's `is_platform_binary` flag is more conservative than any hand-curated path or
signing-id allowlist would be: it is the kernel's own classification of "this binary is on the Apple-signed
system image" and identifies launchd, xpcproxy, fseventsd, kextd, sysextd, systemextensionsd, WindowServer,
loginwindow, mds, and every other Apple system binary without operator-maintained lists.

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

The extension SHALL compute the exec target's SHA-256 synchronously on the AUTH_EXEC callback thread when the
active snapshot contains at least one `BINARY` rule, bounded by a budget derived from the kernel-supplied
`es_message_t.deadline`. The budget SHALL reserve a safety margin (target: 500 ms) for the post-hash work
(snapshot lookup, kernel respond, optional event / notification dispatch) plus an unlucky page-in stall. The
hash SHALL stream the file in chunks (target: 64 KiB) so the deadline budget is checked between chunks and an
abort yields the kernel-respond path enough headroom to complete. When the active snapshot has zero `BINARY`
rules, the extension SHALL skip the hash compute entirely (the result no rule could consult is wasted work).

The TOCTOU re-stat guard from the warm-cache compute path SHALL apply: if `fstat(2)` on the opened file
descriptor reports a `(dev, inode, mtime)` tuple different from what the AUTH event delivered, the extension
SHALL treat the outcome as unavailable (the file was atomically replaced between AUTH and read) and SHALL NOT
poison the cache with a hash of the wrong file.

#### Scenario: Sync hash on cold cache decides the first exec

- **GIVEN** the active snapshot contains a `BINARY` block rule whose identifier is the SHA-256 of a binary the
  extension has never seen before (cache cold)
- **WHEN** the kernel issues an AUTH_EXEC for that binary
- **THEN** the extension computes the SHA-256 synchronously within the kernel deadline budget
- **AND** the precedence walk's BINARY layer matches the rule
- **AND** the extension responds with `ES_AUTH_RESULT_DENY`
- **AND** an `application_control_block` event is emitted

#### Scenario: Mutated `(dev, inode, mtime)` does not bypass the BINARY rule

- **GIVEN** the active snapshot contains a `BINARY` block rule for a binary whose mtime is mutated on every
  exec (an attacker invalidating the cache key to keep the first-exec ALLOW path open)
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

The active snapshot SHALL carry a `deadline_fallback` field whose value is one of `fail-closed`, `fail-open`,
or `audit-only`. When the deadline-bounded SHA-256 cannot complete (the budget is exhausted between chunks)
or returns a read failure (TOCTOU mismatch, missing file, fstat error), the extension SHALL apply the posture
as the terminal verdict for the AUTH_EXEC, without continuing the precedence walk to `SIGNINGID` or `TEAMID`
(the BINARY layer's "could-have-fired" uncertainty dominates anything those lower layers would say).

- `fail-closed`: respond `ES_AUTH_RESULT_DENY`. Emit an `application_control_undecided` event with
  `verdict=deny` so the operator can audit the rate.
- `fail-open`: respond `ES_AUTH_RESULT_ALLOW`. Emit no event (the operator opted out of visibility).
- `audit-only`: respond `ES_AUTH_RESULT_ALLOW`. Emit an `application_control_undecided` event with
  `verdict=allow` so the operator can measure the cold-cache rate without changing exec behaviour.

When the snapshot payload omits the field, the extension SHALL substitute `fail-closed` (the documented
v0.1.0 default; the only posture that closes the cold-cache window without operator awareness of the
trade-off).

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

The extension SHALL emit an event of kind `application_control_undecided` only when the BINARY layer's hash
outcome is unavailable AND the active snapshot's `deadline_fallback` is `fail-closed` or `audit-only`. The
event SHALL carry `pid`, `path`, `verdict` (`allow` for audit-only, `deny` for fail-closed), `reason`
(`deadline` when the budget was exhausted, `read_failed` when the file was unreadable or the TOCTOU re-stat
failed), `file_size_bytes`, `policy_id`, and `policy_version`. The event SHALL be emitted AFTER the kernel
`es_respond_auth_result` call so the post-respond cost does not eat into the deadline.

#### Scenario: read_failed reason on TOCTOU mismatch under fail-closed

- **GIVEN** the active snapshot carries `deadline_fallback=fail-closed` and at least one `BINARY` rule
- **WHEN** the AUTH_EXEC arrives but a `(dev, inode, mtime)` TOCTOU re-stat at hash-open time shows the file
  was replaced
- **THEN** the extension responds `ES_AUTH_RESULT_DENY`
- **AND** emits an `application_control_undecided` event with `verdict=deny` and `reason=read_failed`

## MODIFIED Requirements

### Requirement: Target identifier tuple for every exec

For every authorized exec the extension SHALL build a target identifier tuple consisting of `cdhash`,
`signing_id_prefixed`, `leaf_cert_sha256`, `team_id`, and `path`. `file_sha256` is no longer part of the
tuple struct itself; it is supplied as a separate `HashOutcome` at decide time so the hash compute can run
on the AUTH callback thread under a deadline budget (see the deadline-guarded BINARY hash requirement
above). The remaining tuple values SHALL be derived as follows:

- `cdhash`: the value of `process.cdhash` on `es_process_t`, populated only if the process runs under
  Apple's Hardened Runtime. For non-hardened processes this field SHALL be absent. (Note: this gate is
  ours; Santa applies CDHASH rules regardless of the Hardened Runtime flag. We gate because the kernel
  maps pages lazily on non-hardened processes and does not re-verify them post-load, so the CDHash ESF
  reports at exec is not a reliable identity for the bytes that will eventually execute.)
- `signing_id_prefixed`: `<team_id>:<signing_id>` when both are present, or `platform:<signing_id>` when the
  binary is an Apple platform binary, or absent when no signing_id is present.
- `leaf_cert_sha256`: the SHA-256 of the leaf X.509 certificate in the signed code's signing chain. The
  extension SHALL maintain a cache keyed by `(inode, mtime)` and SHALL NOT block the AUTH callback on the
  fetch. On a cache miss the value MAY be absent for the current exec.
- `team_id`: the value of `process.team_id`, or absent if the binary is unsigned.
- `path`: the canonical absolute filesystem path of the authorized exec target. Always present (the AUTH
  event carries it directly); the macOS canonicalization of `/tmp`, `/var`, and `/etc` into their
  `/private/...` forms is applied before matching so the precedence walk compares against the same canonical
  form the server validates and persists rule identifiers in.

#### Scenario: A signed non-Apple binary yields a full tuple

- **GIVEN** the extension's leaf-cert cache contains an entry for the binary under test
- **WHEN** the extension builds the target tuple for an exec of that binary
- **THEN** the tuple contains `signing_id_prefixed` shaped as `<team_id>:<signing_id>`, `leaf_cert_sha256`,
  and `team_id`
- **AND** `cdhash` is present if the binary uses the Hardened Runtime and absent otherwise

#### Scenario: A first exec with cold leaf-cert cache still produces a tuple but with leaf_cert absent

- **GIVEN** the extension's `leaf_cert_sha256` cache is empty for the binary under test
- **WHEN** the extension builds the target tuple for the exec
- **THEN** the tuple contains at least `team_id` and `signing_id_prefixed` where present
- **AND** `leaf_cert_sha256` is absent
- **AND** the missing leaf-cert value does not delay the AUTH callback

#### Scenario: A platform binary's signing identifier carries the platform prefix

- **GIVEN** an exec of `/usr/bin/curl` (signed as an Apple platform binary)
- **WHEN** the extension builds the target tuple
- **THEN** `signing_id_prefixed` is `platform:com.apple.curl`

### Requirement: AUTH_EXEC denial on BLOCK match

When the precedence walk returns a rule whose `action=BLOCK` and `enforcement=PROTECT`, the extension SHALL
deny the AUTH_EXEC request so the new image does not run. When the walk returns no match, or returns a rule
whose `enforcement` is anything other than `PROTECT`, the extension SHALL allow the AUTH_EXEC request to
proceed. The decision SHALL be reached within the AUTH_EXEC deadline. The extension MAY block the AUTH
callback on a synchronous BINARY-rule SHA-256 compute bounded by the deadline budget (see the deadline-
guarded BINARY hash requirement). The extension MUST NOT block the AUTH callback on `leaf_cert_sha256`
fetches; those remain a lazy cache fill.

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

### Requirement: Lazy signing-info fetch is non-blocking (scope narrowed to leaf_cert only)

The extension SHALL compute `leaf_cert_sha256` outside of the AUTH_EXEC callback whenever the value is not
already cached. When the value is not cached at decision time, the `CERTIFICATE` rule type SHALL silently
miss for that exec, and the resulting cache entry SHALL be available to subsequent execs of the same
`(inode, mtime)`. The extension MUST NOT call into Security framework lookups inside the AUTH_EXEC callback.

(The Phase A rule that grouped `file_sha256` under this same "lazy, non-blocking" contract is REMOVED:
`file_sha256` is now computed synchronously on the AUTH callback thread under the deadline budget defined
by the deadline-guarded BINARY hash requirement above. The lazy-fill `startLazyFill` path on
`FileHashCache` remains as a warm-up optimisation for the NOTIFY_EXEC path's `lookupOrCompute` call, NOT
as a substitute for AUTH-time enforcement.)

#### Scenario: A cold CERTIFICATE cache yields a silent miss then a warm hit

- **GIVEN** the `leaf_cert_sha256` cache is empty for a binary under test
- **WHEN** the binary is executed for the first time
- **THEN** any `CERTIFICATE` rule that would have matched silently misses for that exec
- **AND** the cache is filled after the AUTH callback returns
- **WHEN** the same binary is executed a second time
- **THEN** the `CERTIFICATE` rule matches and the AUTH callback returns deny within the deadline
