# Detection-config hardening (follow-ups to #459)

## Why

Issue #459 shipped the DB-backed detection-config surface (typed exclusions + per-rule modes). Issue #482 tracks the deferred follow-ups. This change delivers the two that are concrete and self-contained:

- **Path canonicalization.** `path_glob` / `parent_path_glob` exclusions did not account for the macOS `/private` firmlink: an exclusion written as `/etc/...` silently failed to match an event ESF reported as `/private/etc/...` (and vice versa), so an operator's allowlist could appear to do nothing. The matcher now tests the operator's glob against both macOS forms of the concrete candidate path.
- **Cross-replica convergence.** The in-memory detection-config snapshot reloaded only on a local mutation, so under the multi-replica topology (ADR-0010) a replica that did not handle the mutating request served a stale config until its next local mutation or a restart. A periodic version-poll now converges every replica.

The remaining #482 items (typed per-rule settings schema, host-group-scoped config + exclusion editing) stay deferred: the schema is speculative until a rule needs a tunable knob, and host-group scope is blocked on editable host groups.

## What changes

- `api.MatchExclusionValue` aliases the concrete candidate path across `/etc`|`/var`|`/tmp` <-> `/private/...` at match time for the two path match types. The glob entry is never rewritten (globs cannot be canonicalized cleanly), so a non-aliasable path costs at most one extra match.
- `detectionconfig.Service` gains a `RefreshLoop(ctx, interval)` that polls `detection_config_meta.version` (a single indexed-row read) and reloads only when the version advanced past the loaded snapshot's. The rules context exposes `Run(ctx)`; `cmd/main` starts it alongside the other contexts' background loops.

## Impact

- Behavior: exclusions match regardless of firmlink form; replicas converge within the refresh interval (default 5s). No wire-format or schema change.
- Tests: unit (matcher aliasing), rule-layer regression (sudoers_tamper), integration (two-replica convergence over a real database).
