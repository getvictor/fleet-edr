# Extension Application Control Specification

## ADDED Requirements

### Requirement: Decided ALLOW is cached and flushed on snapshot replacement

The extension SHALL respond to a FULLY RESOLVED decided ALLOW and to the self-allow failsafe with `es_respond_auth_result(..., cache: true)`, pinning the result into the kernel's per-`(dev, inode, mtime)` AUTH cache so subsequent execs of the same binary do not re-enter the handler. An allow is fully resolved only when every lazily-resolved identity component the active snapshot could consult was available at decision time: the BINARY hash was computed (or not needed because the snapshot has no BINARY rules), AND either the snapshot has no CERTIFICATE rules or the leaf certificate was resolved. The extension SHALL respond with `cache: false` to a cold-miss ALLOW (a BINARY hash that timed out or could not be read under a fail-open posture, or a CERTIFICATE rule that silently missed a not-yet-cached leaf certificate), to an undecided ALLOW, and to every DENY: a cold-miss ALLOW must let the next exec re-evaluate once the hash or certificate warms so a block rule can still fire, an undecided ALLOW does not yet know the identity, and a cached DENY would survive a block-rule removal. Whenever the active application-control snapshot is replaced (any accepted apply: a version advance, an epoch-axis re-sync, or a policy retarget), the extension SHALL flush the kernel AUTH cache via `es_clear_cache` so a cached ALLOW cannot outlive a rule change; a snapshot apply rejected by the recency gate SHALL NOT trigger a flush.

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

#### Scenario: A denial is not cached

- **GIVEN** the decision is a denial (a matched block rule or an undecided deny under fail-closed posture)
- **WHEN** the extension forms the AUTH_EXEC response
- **THEN** the cacheable flag for that response is false

#### Scenario: Replacing the active snapshot flushes the kernel auth cache

- **GIVEN** an active application-control snapshot and a wired cache-flush hook
- **WHEN** a newer snapshot is accepted by the recency gate (version advance, epoch re-sync, or policy retarget)
- **THEN** the kernel AUTH cache flush fires once per accepted swap
- **AND** a stale snapshot rejected by the recency gate does not fire the flush
