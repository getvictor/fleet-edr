# Extension application control delta

## ADDED Requirements

### Requirement: Detect-mode rules report would-block matches

When the precedence walk for an AUTH_EXEC matches a `BLOCK` rule whose `enforcement` is `DETECT`, the extension SHALL continue the walk rather than end it, and SHALL record the first such match in precedence order. A `DETECT` rule SHALL NOT change the verdict: the verdict for any exec SHALL be the verdict the same snapshot reaches with its `DETECT` rules removed, so a `PROTECT` rule at any precedence still denies and the deadline fallback posture still governs an unresolved BINARY hash.

When the verdict allows the exec and a `DETECT` rule was matched, the extension SHALL emit an `application_control_would_block` event for that match. The event SHALL carry the fields of `application_control_block`: `policy_id`, `policy_version`, `rule_id`, `rule_type`, `identifier`, `severity`, `pid`, and `path`, plus `custom_msg` and `custom_url` when the matched rule sets them. The `identifier` SHALL be the value from the target tuple that matched the `DETECT` rule. The extension SHALL NOT present the desktop block notification for a would-block match, and SHALL NOT emit a would-block event for an exec it denies.

#### Scenario: A DETECT rule allows and reports the exec

- **GIVEN** the only rule an exec matches is a `BLOCK` / `DETECT` rule
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is allow
- **AND** an `application_control_would_block` event names the rule
- **AND** no desktop notification is presented

#### Scenario: A would-block match names the matched identifier

- **GIVEN** a `TEAMID` rule with `enforcement=DETECT` for `EQHXZ8M8AV` matches an exec
- **WHEN** the extension evaluates the exec
- **THEN** the reported match's `rule_type` is `TEAMID`
- **AND** its `identifier` is `EQHXZ8M8AV`

#### Scenario: A DETECT rule does not weaken a PROTECT rule

- **GIVEN** an exec matches a `DETECT` rule and a lower-precedence `PROTECT` rule
- **WHEN** the extension responds to AUTH_EXEC
- **THEN** the response is deny, naming the `PROTECT` rule
- **AND** no would-block match is reported

#### Scenario: The highest-precedence DETECT match is reported

- **GIVEN** an exec matches a `SIGNINGID` rule and a `TEAMID` rule, both with `enforcement=DETECT`
- **WHEN** the extension evaluates the exec
- **THEN** the reported match is the `SIGNINGID` rule

#### Scenario: The fallback posture still applies

- **GIVEN** the snapshot has BINARY rules, the exec's hash could not be computed before the deadline, and the exec matches a lower-precedence `DETECT` rule
- **WHEN** the extension evaluates the exec
- **THEN** under `fail-closed` the exec is denied as undecided and no would-block match is reported
- **AND** under `fail-open` the exec is allowed and the would-block match is reported
- **AND** under `audit-only` the exec is allowed, the undecided event is emitted, and the would-block match is reported

## MODIFIED Requirements

### Requirement: AUTH_EXEC denial on BLOCK match

When the precedence walk returns a rule whose `action=BLOCK` and `enforcement=PROTECT`, the extension SHALL deny the AUTH_EXEC request so the new image does not run. A `BLOCK` rule whose `enforcement=DETECT` SHALL NOT end the walk (see the Detect-mode requirement). When the walk matches no `PROTECT` rule, or ends on a rule whose `action` or `enforcement` is a value the server does not create, the extension SHALL allow the AUTH_EXEC request to proceed, subject to the deadline fallback posture. The decision SHALL be reached within the AUTH_EXEC deadline. The extension MAY block the AUTH callback on a synchronous BINARY-rule SHA-256 compute bounded by the deadline budget (see the deadline-guarded BINARY hash requirement). The extension MUST NOT block the AUTH callback on `leaf_cert_sha256` fetches; those remain a lazy cache fill.

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

### Requirement: Decided ALLOW is cached and flushed on snapshot replacement

The extension SHALL respond to a FULLY RESOLVED decided ALLOW and to the self-allow failsafe with `es_respond_auth_result(..., cache: true)`, pinning the result into the kernel's per-`(dev, inode, mtime)` AUTH cache so subsequent execs of the same binary do not re-enter the handler. An allow is fully resolved only when every lazily-resolved identity component the active snapshot could consult was available at decision time: the BINARY hash was computed (or not needed because the snapshot has no BINARY rules), AND either the snapshot has no CERTIFICATE rules or the leaf certificate was resolved. The extension SHALL respond with `cache: false` to a cold-miss ALLOW (a BINARY hash that timed out or could not be read under a fail-open posture, or a CERTIFICATE rule that silently missed a not-yet-cached leaf certificate), to an undecided ALLOW, to an ALLOW that matched a `DETECT` rule, and to every DENY: a cold-miss ALLOW must let the next exec re-evaluate once the hash or certificate warms so a block rule can still fire, an undecided ALLOW does not yet know the identity, a cached ALLOW that matched a `DETECT` rule would leave every later exec of the binary unreported, and a cached DENY would survive a block-rule removal. Whenever the active application-control snapshot is replaced (any accepted apply: a version advance, an epoch-axis re-sync, or a policy retarget), the extension SHALL flush the kernel AUTH cache via `es_clear_cache` so a cached ALLOW cannot outlive a rule change; a snapshot apply rejected by the recency gate SHALL NOT trigger a flush.

#### Scenario: A decided allow is cached at the kernel

- **GIVEN** a decided allow whose identity was fully resolved (BINARY hash computed or not needed, and the leaf certificate resolved or no CERTIFICATE rules present)
- **WHEN** the extension forms the AUTH_EXEC response
- **THEN** the cacheable flag for that response is true

#### Scenario: A cold-miss allow is not cached

- **GIVEN** an allow reached while a lazily-resolved identity component was still cold (the BINARY hash timed out or could not be read, or a CERTIFICATE rule silently missed a not-yet-cached leaf certificate)
- **WHEN** the extension forms the AUTH_EXEC response
- **THEN** the cacheable flag for that response is false, so the next exec re-evaluates once the hash or certificate warms

#### Scenario: An undecided allow is not cached

- **GIVEN** the decision is an undecided allow (cold cache, deadline exceeded, or read failure under an allow-leaning posture)
- **WHEN** the extension forms the AUTH_EXEC response
- **THEN** the cacheable flag for that response is false

#### Scenario: A detect-match allow is not cached

- **GIVEN** a fully resolved allow that matched a `DETECT` rule
- **WHEN** the extension forms the AUTH_EXEC response
- **THEN** the cacheable flag for that response is false, so the next exec of the binary is reported too

#### Scenario: A denial is not cached

- **GIVEN** the decision is a denial (a matched block rule or an undecided deny under fail-closed posture)
- **WHEN** the extension forms the AUTH_EXEC response
- **THEN** the cacheable flag for that response is false

#### Scenario: Replacing the active snapshot flushes the kernel auth cache

- **GIVEN** an active application-control snapshot and a wired cache-flush hook
- **WHEN** a newer snapshot is accepted by the recency gate (version advance, epoch re-sync, or policy retarget)
- **THEN** the kernel AUTH cache flush fires once per accepted swap
- **AND** a stale snapshot rejected by the recency gate does not fire the flush
