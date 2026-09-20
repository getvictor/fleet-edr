# A forked process carries its parent's code-signing identity

Issue #1123. A process created by `fork` and never `exec`ed carries no code-signing record, so every signature-based exclusion (`team_id`, `signing_id`, `cdhash`) silently misses it, even though the image it is running is its parent's and that parent's signature is known.

Measured on edr-dev during the #1024 QA. Of the `sshd-session` rows on that host, 883 carried a signature and 896 carried NULL, and the split is exactly whether an exec event was seen: a row with `exec_event_id` has the identity, a fork-only row has none. `sshd` forks a child per connection and that child serves the session without exec'ing. The fork event already seeds the row's `path` from the parent, correctly, because a forked child does run the parent's image. It left `code_signing`, `sha256` and `cdhash` NULL.

The effect on an operator is worse than a missing field. `parentExcluded` reads the parent's persisted signing record, and a parent that carries none is correctly not suppressed, so writing `team_id = <vendor>` to silence a noisy signed tool suppresses its exec'd instances and alerts on its forked ones, with nothing in the product explaining the difference. The exclusion looks broken and intermittent.

It also blocked QA: confirming #1024's `platform:` qualifier on a real host needs a platform-signed non-shell parent, and the obvious candidate is `sshd-session`, which is fork-only on exactly the SSH-driven chains that matter.

## What changes

- **A fork-only row inherits its parent's `code_signing`, `sha256` and `cdhash`**, alongside the path it already inherited, resolved by the same lookup and therefore from the same generation and the same image within a re-exec chain. Inheriting one half of an image and not the other is what produced a row naming a binary with no signature for it.
- **`GetParentPath` becomes `GetParentImage`**, returning the whole image rather than its path. One lookup, one ordering, both implementations: the resolution is the product of two issues' worth of measurement (#714, #861) and a second copy of it selecting the identity would drift from the copy selecting the path.
- **A parent with no identity still yields none.** Inheritance copies what the parent has, including nothing.

## Decided here

**Write time, not read time.** The value is stored on the fork row. Resolving it at read time would leave every other reader of the row (the process tree, the process detail view, an export) still seeing NULL while the rules engine saw an identity, which is a worse inconsistency than a stored derived value. It also matches what already happens to the path.

**An inherited identity is distinguishable from an observed one, and needs no new column to be.** A row whose `exec_event_id` is NULL has never been imaged by an exec, so its identity can only have been inherited; a row with one carries what that exec observed. That is the same discriminator the issue used to measure the split, it is already persisted, and adding a flag beside it would be a second encoding of a fact the row already states.

**No backfill.** Existing fork-only rows keep their NULL identity. A backfill would have to re-resolve each row's parent at its own fork timestamp against a table that has since been pruned, and the answer for a row whose parent is gone would be a guess. Rows written from here on carry the identity; older ones stay honestly empty.

**Snapshot rows are ordinary parents.** A snapshot row's identity is observed, from the enumeration that produced it, so a child forked from one inherits a real identity. Nothing about `is_snapshot` changes here.

## Why this is correct and not an approximation

A forked child runs its parent's image until it execs. That is what `fork` means, and it is why the path was already inherited. `UpdateProcessExec` overwrites `code_signing`, `sha256` and `cdhash` unconditionally, so an exec that follows replaces all three and no inherited identity can survive across an exec boundary.

## Out of scope

- Backfilling historical rows.
- Any change to how an exclusion treats a parent that carries no identity: that fail-safe stays exactly as it is, and this change simply means fewer parents reach it empty.
