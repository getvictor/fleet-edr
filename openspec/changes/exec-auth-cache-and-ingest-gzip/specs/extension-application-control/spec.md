# Extension Application Control Specification

## ADDED Requirements

### Requirement: Decided ALLOW is cached and flushed on snapshot replacement

The extension SHALL respond to a fully decided ALLOW (the precedence walk returned no block and the verdict is allow) and to the self-allow failsafe with `es_respond_auth_result(..., cache: true)`, pinning the result into the kernel's per-`(dev, inode, mtime)` AUTH cache so subsequent execs of the same binary do not re-enter the handler. The extension SHALL respond to an undecided ALLOW (cold-cache, deadline-exceeded, or read-failure fallback) and to every DENY with `cache: false`, because an undecided ALLOW does not yet know the identity and a cached DENY would survive a block-rule removal. Whenever the active application-control snapshot is replaced (any accepted apply: a version advance, an epoch-axis re-sync, or a policy retarget), the extension SHALL flush the kernel AUTH cache via `es_clear_cache` so a cached ALLOW cannot outlive a rule change; a snapshot apply rejected by the recency gate SHALL NOT trigger a flush.

#### Scenario: A decided allow is cached at the kernel

- **GIVEN** the precedence walk against the active snapshot returns a decided allow
- **WHEN** the extension forms the AUTH_EXEC response
- **THEN** the cacheable flag for that response is true

#### Scenario: An undecided allow is not cached

- **GIVEN** the decision is an undecided allow (cold cache, deadline exceeded, or read failure under an allow-leaning posture)
- **WHEN** the extension forms the AUTH_EXEC response
- **THEN** the cacheable flag for that response is false

#### Scenario: A denial is not cached

- **GIVEN** the decision is a denial (a matched block rule or an undecided deny under fail-closed posture)
- **WHEN** the extension forms the AUTH_EXEC response
- **THEN** the cacheable flag for that response is false

#### Scenario: Replacing the active snapshot flushes the kernel auth cache

- **GIVEN** an active application-control snapshot and a wired cache-flush hook
- **WHEN** a newer snapshot is accepted by the recency gate (version advance, epoch re-sync, or policy retarget)
- **THEN** the kernel AUTH cache flush fires once per accepted swap
- **AND** a stale snapshot rejected by the recency gate does not fire the flush
