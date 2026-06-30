# Architecture anti-patterns

**Cadence:** quarterly **Time budget:** 90 min **Trigger mode:** manual

## Why this matters

[`architecture-drift`](architecture-drift.md) asks one question: is context A reaching into context B (boundary integrity, horizontal). This task asks a different one: is the design _shaped_ well, inside and across contexts (structural soundness, vertical). A codebase can pass `arch-go` and the drift audit with every import clean and still be a big ball of mud: business logic smeared into HTTP handlers, an interface with one implementation invented "for the future", a `string` where a domain type belongs, a package-level map quietly holding cross-request state that ADR-0010 forbids.

This repo is largely AI-generated, which makes two anti-patterns the dominant risk (CLAUDE.md already names them): **speculative generality** (abstractions and defensive branches for callers that do not exist) and **semantic re-implementation** (the same logic regrown under a new name). The second is owned by [`consolidation-pass`](consolidation-pass.md); this task owns the first and the rest of the structural-design catalog. No linter expresses "this interface should not exist" or "this logic is in the wrong layer"; this task is the human-judgment net under those.

## Relationship to sibling tasks (stay in lane)

To avoid maintenance theatre, do NOT re-litigate what these already cover. Cross-reference, do not duplicate:

- [`architecture-drift`](architecture-drift.md): cross-context imports, internal-package leaks, god-tables/god-structs in `api/`, conceptual coupling across the `api/` boundary. If a finding is "context A knows context B's schema", it belongs there.
- [`consolidation-pass`](consolidation-pass.md): semantic duplication and cognitive-complexity hotspots in live code.
- [`config-surface-review`](config-surface-review.md): dead or wrong-layer config knobs.
- [`dead-code-sweep`](dead-code-sweep.md): orphan packages, unused exports.

This task is for the design wrong-turns those miss: wrong-layer logic, premature abstraction, anemic/god split, distributed-monolith state, leaky or reversed abstractions, primitive obsession, feature envy.

## Scope

`server/` (all five contexts), `agent/`, `internal/`, `api/` packages. The Swift extension (`extension/`, `shared/`) is in scope for the layering and god-object checks but not the Go-specific heuristics.

## Anti-pattern catalog

The checklist this task scans for. Each entry names the smell, the EDR-specific shape it tends to take, and the ADR (if any) that makes it either a real finding or an intentional, documented choice. Keep this catalog current via step 6.

| Anti-pattern | EDR-specific shape | Verdict gate |
| --- | --- | --- |
| **Wrong-layer logic** | SQL string outside a `mysql`/`store`/`migrations` package; branching business logic inside an HTTP handler that should only decode, delegate, encode | Real finding |
| **Premature abstraction / speculative generality** | Interface with exactly one implementation and one caller; a "strategy"/"provider" seam with one option; a defensive branch no caller can reach (CLAUDE.md "No speculative edge cases") | Real finding unless an ADR names the second implementation as imminent |
| **Distributed monolith / shared mutable state** | Package-level `map`/`chan`/slice holding state that survives a request and a peer replica would need (ADR-0010, ADR-0011) | Real finding unless carrying a "per-replica perf cache, safe to lose" note |
| **Anemic vs god split** | A domain struct that is pure data while a single `service.go` holds every behaviour for that struct | Judgment: anemic structs are often idiomatic Go. Flag only when the god-service is the join point of many features |
| **Leaky / reversed abstraction** | `api/` type exposing raw implementation fields; an interface in package A satisfied only by package B which depends on A (the imports are clean, the dependency is a circle) | Real finding (reversal overlaps drift, cross-reference) |
| **Primitive obsession** | `string` host IDs / `int` enums threaded through `api/` signatures where a named domain type exists | Real finding when a domain type already exists and is bypassed |
| **Feature envy / inappropriate intimacy** | A function in package A that takes a B type and only reads its fields; logic that "wants" to live in B | Judgment, flag the clear cases |
| **Synchronous coupling where async is the design** | Inline enforcement / command paths blocking on a dependency whose failure semantics ADR-0014 / ADR-0016 define as fire-and-forget | Real finding when it contradicts the ADR |
| **Reinvented stdlib / framework** | Hand-rolled retry, set, ring buffer, or JSON walk that the stdlib or an existing `internal/` helper already provides | Real finding (run `find-prior-art` before proposing the replacement) |

## Steps

### 1. Refresh intent

Skim the ADR index (`docs/adr/README.md`) and the load-bearing ones for this task: ADR-0004 (contexts), ADR-0010 (stateless), ADR-0011 (HA), ADR-0014 (inline enforcement), ADR-0016 (event substrate). These decide whether a smell is a finding or a documented choice. A "global mutable map" is a defect; an explicit "per-replica perf cache, safe to lose" is not. You cannot judge the catalog's verdict gates without this.

### 2. Wrong-layer scan

```bash
# SQL outside the persistence layer.
grep -rnE '"\s*(SELECT|INSERT|UPDATE|DELETE)\b' server/ --include='*.go' \
  | grep -vE '/(mysql|store|migrations|tests)/' | grep -v '_test.go'

# Handler files doing more than decode -> delegate -> encode (loops / SQL / multi-branch business logic).
grep -rlnE 'func .*http|Handler' server/ --include='*.go' | grep -v '_test.go' \
  | xargs grep -lnE '\bfor \b|"\s*(SELECT|INSERT)' 2>/dev/null
```

Any hit is a candidate. Confirm by reading: a handler that ranges over a decoded slice to build a response is fine; one that runs the core domain decision is wrong-layer.

### 3. Speculative-abstraction scan

```bash
# Interfaces: each declared interface is a candidate. The smell is one-impl + one-caller.
grep -rnE '^\s*type \w+ interface' server/ agent/ internal/ --include='*.go' | grep -v '_test.go'
```

For each interface, ask: how many concrete types implement it, and how many call sites pass more than one of those types? An interface with one implementation and no test double that exercises a second is speculative generality. Inline it unless an ADR names the imminent second implementation. Apply the same lens to "provider"/"strategy"/"factory" seams with a single option.

### 4. Distributed-monolith state scan

```bash
# Package-level mutable state that may outlive a request (ADR-0010 violation surface).
grep -rnE '^var \w+ +(map\[|chan |\[\])' server/ --include='*.go' | grep -v '_test.go'
```

For each, decide: is this request-scoped, immutable-after-init, or a "safe to lose" per-replica cache? If none of those and a second replica would serve a stale or wrong answer, it is a distributed-monolith defect. File it.

### 5. Primitive-obsession and feature-envy spot check

Pick the 3 most-imported `api/` types. For their constructor and method signatures, count raw `string`/`int`/`bool` parameters that have a named domain type elsewhere in the tree (host ID, alert status, principal). Threading the primitive past an existing type is the smell. Then sample 2-3 functions that take a foreign-package type as their main argument: if the body only reads that type's fields and never its own package's state, that logic envies the other package.

### 6. New search for latest architectural guidance and anti-patterns

Industry awareness, not a duty to adopt. Use WebSearch / WebFetch on the last ~12 months and ask one question of each source: does it name a structural anti-pattern (or retire one) that this catalog is missing or has wrong?

- **Thoughtworks Technology Radar** (architecture quadrant): what moved to Hold, what to Adopt.
- **Martin Fowler / refactoring.com**: the canonical smell catalog, any additions.
- **"Software Architecture: The Hard Parts" / "Fundamentals of Software Architecture"** (Ford, Richards) and their fitness-function writing: distributed-monolith and modular-monolith failure modes.
- **Modular monolith** practitioner writing (e.g. Milan Jovanovic, Shopify / GitHub engineering on monolith decomposition): the failure modes a modular monolith hits before it earns microservices.
- **Cloud Well-Architected frameworks** (AWS / Google / Azure) reliability + operational-excellence pillars: only the parts that bear on a stateless multi-replica server.
- **Go-specific**: Go team blog, Go proverbs, "accept interfaces return structs" guidance, any shift in idiomatic layering.

Update the catalog table in this file for any genuine delta (add a row, fix a verdict gate, retire a smell that is now considered fine). This keeps the task self-current. Note the delta count in the log.

### 7. Self-review (mandatory before filing anything)

This codebase punishes false positives: flagging an intentional design as an "anti-pattern" is itself the noise this schedule exists to prevent. Before any finding leaves this session, run each one through this gate and drop the ones that fail:

- **Concrete cost.** Can I name the real bug, the real maintenance tax, or the real future-incident path this causes? "It is a textbook smell" is not a cost. If I cannot point at the harm, drop it.
- **ADR check.** Did I confirm an ADR does not already bless this as intentional? Stateless-server-holds-no-state, MySQL-only, OTel-only, anemic Go structs: these are decisions, not defects. A finding that contradicts a documented choice is an ADR-amendment proposal, not a refactor.
- **Go idiom.** Am I importing an OO smell that does not apply to Go? Anemic structs, "no getters/setters", small interfaces at the consumer: these are idiomatic here. Do not flag them.
- **Skeptic test.** Would this survive a reviewer asking "show me the caller / input that makes this hurt"? (Same bar CLAUDE.md sets for defensive branches.) If I cannot produce it, the finding is itself speculative.
- **Proportionality.** Is the proposed fix smaller than the anti-pattern's cost? If the refactor is a multi-day rework, file an issue and stop (README rule 3: refuse compounded scope). Do not start it inside this 90-minute budget.

Write the surviving findings only. State in the PR / log how many candidates were dropped at this gate and why, so the self-review is auditable.

## Output

- One PR per refactor small enough to land safely inside the budget.
- Issues filed for each refactor that is not.
- Catalog table updated for any real delta from step 6.
- An ADR-amendment candidate filed if a finding contradicts a documented decision.
- A dated entry in [`docs/maintenance/log.md`](../log.md) on every run, whether findings landed or not, with the candidate count and the dropped-at-self-review count. "No findings" is signal that the layering and the AI-generation guardrails are holding.

## Prompt template

```text
Run the architecture-anti-patterns audit defined in docs/maintenance/tasks/architecture-anti-patterns.md.

Step 1 - skim docs/adr/README.md plus ADR-0004, 0010, 0011, 0014, 0016 so you can tell a defect from a
documented choice.

Step 2 - wrong-layer scan: SQL outside persistence packages, business logic inside HTTP handlers.

Step 3 - speculative-abstraction scan: interfaces / provider seams with one implementation and one caller.
Inline candidates unless an ADR names the imminent second implementation.

Step 4 - distributed-monolith scan: package-level mutable maps/chans/slices that outlive a request and
a second replica would need (ADR-0010 / ADR-0011).

Step 5 - primitive-obsession + feature-envy spot check on the 3 most-imported api/ types.

Step 6 - NEW SEARCH for latest architectural guidance and anti-patterns (last 12 months): Thoughtworks
Tech Radar, Martin Fowler / refactoring.com, "The Hard Parts" / "Fundamentals of Software Architecture",
modular-monolith practitioner writing, cloud Well-Architected reliability pillars, Go idiom shifts. Use
WebSearch / WebFetch. Update the catalog table in the task file for any genuine delta.

Step 7 - SELF-REVIEW every candidate before filing: concrete cost named? not blessed by an ADR? not an
OO smell that is idiomatic in Go? survives "show me the caller that makes this hurt"? fix smaller than
the cost? Drop the ones that fail and record how many were dropped and why.

For each surviving finding decide: refactor in this PR / file an issue / amend an ADR / accept and
document. Open one PR for the refactors and a tracking issue for the rest.

Hard rule: every run appends a dated entry to docs/maintenance/log.md, even with no findings, including
the candidate count and the dropped-at-self-review count.
```

## Definition of done

- [ ] Wrong-layer, speculative-abstraction, distributed-monolith, and primitive-obsession/feature-envy scans run.
- [ ] Latest-guidance search covered the listed sources; catalog table updated for any delta.
- [ ] Self-review gate applied to every candidate; dropped count recorded with rationale.
- [ ] Each surviving finding has a decision (refactor / issue / ADR amendment / accept).
- [ ] Dated entry in [`docs/maintenance/log.md`](../log.md) with candidate count and dropped count. </content> </invoke>
