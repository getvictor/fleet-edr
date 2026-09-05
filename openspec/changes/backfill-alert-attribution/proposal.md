# Credit alerts raised by a vendored rule before attribution was recorded

## Why

`alerts.origin` has been populated going forward since rule attribution shipped (#824, migration 00012) and was never backfilled. An operator who promoted a vendored rule and then upgraded keeps alerts that display no credit at all, which leaves the Detection Rule License obligation unmet for exactly those rows.

#824 measured the affected population at ZERO across both dev lanes and deliberately did not build this, which was the right trade then. The set is empty in practice because vendored rules ship in monitor mode (#764), monitor resolution returns before persistence, and promotion only became possible in #814. It is not empty by CONSTRUCTION, and #814 ships in this release, so the population stops being hypothetical the moment an operator promotes a rule.

## What changes

A boot-time pass credits alerts whose origin was never recorded, for vendored rules only.

## Scope, which is the whole risk

The statement itself is unremarkable. What matters is which rules are in scope, because both exclusions write something irreversible into an operator's alert history if they are wrong, and neither is visible in the SQL:

- **Our own rules are excluded.** Migration 00012 deliberately distinguishes an alert raised BEFORE attribution existed from one raised by us, both of which would otherwise be indistinguishable. Filling ours destroys that distinction with no way back.
- **Projections are excluded.** An application-control block stores an empty origin on purpose, because its `rule_id` is the operator's own policy entry. Crediting this project for it claims authorship of their blocklist, which is the bug review caught in #824.

Both fall out of asking `AlertOriginOf` per rule and skipping the empty and project answers, which is why the scope decision is a named function with its own tests rather than a loop inside the caller.

## Shape

A one-shot under `DoOnceIfLeader` rather than a fourth leader-gated loop. The work is finite and finished after one pass, a replica that loses the race has nothing to wait for, and a gated loop would hold a pooled connection for the process lifetime that a one-shot has no business claiming.

Only rows with an empty origin are touched, so the pass cannot overwrite an attribution already recorded and re-running it is a no-op. That is what makes it safe to leave in place rather than something to remove after one release.

A failure does not stop the server. The obligation is real, but an unpaid credit on historical rows is not a reason to refuse to detect anything today, and the next boot tries again.
