# 0021. Rule content is its own bounded context, carved when it acquires storage

- Status: Accepted
- Date: 2026-08-29
- Deciders: getvictor

This amends [0004](0004-modular-monolith-bounded-contexts.md): an eighth context, `rulecontent`, carved out of `rules`. It follows the pattern of [0015](0015-clickhouse-visibility-store.md), which carved `visibility` out of `detection` when a subdomain acquired its own store.

## Context

The rule-format epic (#756) converts the detection catalog from Go code into declarative rule files across six phases. Phase 1 has landed: every detection exports as a rule file (#757), and non-detections are excluded from the catalog surface (#775). Phases 2 through 4 move rule data into those files, add a Sigma evaluator, and import community content. Phase 5 (#766, #767, #768) makes rule packs load at runtime, lets operators author rules, and versions the packs.

The question is whether rule content belongs in the `rules` context or in one of its own, and the honest answer depends on the phase.

**Today it belongs in `rules`, and the export code is the proof.** `export` renders `api.RuleMetadata` as YAML. It owns no model, persists nothing, and has no vocabulary of its own; strip `rules` away and it has nothing to describe. It is a second representation of the same aggregate, which is the textbook case for staying inside a context rather than leaving it. Carving a context for it now would mean a new `api/`, `bootstrap/`, and `testkit/`, plus an `arch-go.yml` dependency block, so that `rules` could call out to something that immediately calls back into `rules`.

**Phase 5 changes every one of those facts.** Rule content stops being a projection and becomes an independently-owned aggregate:

- **It acquires storage.** Rule packs, their versions, and their provenance are durable state that no existing context owns. This is the same trigger [0015](0015-clickhouse-visibility-store.md) used: a subdomain that grows its own store has stopped being a view of someone else's.
- **It acquires a lifecycle orthogonal to evaluation.** Draft, validate, publish, roll back, re-sync from upstream. None of that is a detection concern, and the engine is indifferent to all of it.
- **It acquires a trust boundary.** Operator-authored and community-imported content is untrusted input: catastrophic regex backtracking, unbounded lists, a rule matching everything. A compiled-in Go rule has none of these properties, so the two live under materially different security postures.
- **It acquires its own ubiquitous language.** Packs, versions, authors, licences, upstream sync, attribution. Against the `rules` vocabulary of detections, findings, exclusions, and severities.
- **It acquires an obligation `rules` does not have.** Imported SigmaHQ content ships under the Detection Rule License, which requires crediting the rule's author wherever its matches are shown (#765). That is a property of content provenance, not of evaluation.

The relationship between the two is a clean supplier and consumer: `rulecontent` produces rule definitions, `rules` consumes and evaluates them. That is exactly the seam an `api/` boundary expresses well, and it already has a precedent in the tree, where `rules` consumes `detection/api`'s `GraphReader` as a published read surface.

Deciding this now rather than at implementation time matters because Phase 5's issues are already written. Discovering the boundary mid-implementation means either retrofitting it under delivery pressure or, more likely, not retrofitting it and leaving `rules` carrying two subdomains, which is the state [0015](0015-clickhouse-visibility-store.md) had to unwind for `detection`.

## Decision

Rule content becomes an eighth bounded context, `rulecontent`, carved out of `rules`. **The carve happens in Phase 5, at #766 (runtime rule packs), and not before**, because #766 is where rule content acquires the storage that makes it an aggregate rather than a projection.

`rulecontent` owns rule definitions as durable content: packs and their versions, provenance and attribution, import from upstream sources, validation of untrusted rule content, the authoring lifecycle, and the rule-file serialisation that today lives in `rules/internal/export`.

`rules` retains rule _evaluation_: the `Rule` interface, the engine-facing `RuleProvider`, the operator catalog surface, per-rule tuning (`detectionconfig`), and application-control policy. It consumes rule definitions through `rulecontent/api` the way it consumes the process graph through `detection/api`.

Phases 2 through 4 stay inside `rules`. They extend the existing catalog rather than introducing storage, and moving code twice costs more than moving it once at the point the boundary becomes real.

## Consequences

**Easier.** Untrusted-content validation gets a home with a boundary around it, rather than being a set of guards scattered through the rules service. Pack versioning and rollback become a lifecycle on an aggregate that owns its own state. Attribution and licence obligations attach to provenance, where they belong, instead of riding along on evaluation metadata. `rules` stops accreting a second subdomain, which is the failure mode ADR-0015 documented for `detection`.

**Harder.** Two contexts must be wired where one was, and the split lands mid-epic: #766 becomes a carve plus a feature rather than just a feature, and its estimate should reflect that. Every rule definition crossing the boundary pays an `api/` translation, so the engine's rule-loading path gains an indirection that today is a slice.

**Worse, and worth saying plainly.** The rule-file serialisation moves twice: into `rules/internal/export` in Phase 1, out to `rulecontent` in Phase 5. That is a real cost, accepted because the alternative was inventing a context in Phase 1 around code that owns no data, and because the move is mechanical (one package, one caller in `bootstrap`, one HTTP handler).

**Deferred, deliberately.** Whether the operator-facing HTTP surface for authoring lives in `rulecontent` or stays in the `rules` operator handler is not decided here. It depends on how much the authoring UI shares with the tuning UI, which #767 will make apparent.

## Alternatives considered

**Carve it now, in Phase 1.** Attractive because the boundary would exist before code accumulates on the wrong side of it, and no package would move twice. Rejected because the thing being separated does not yet exist: export owns no data, no lifecycle, and no vocabulary, so the context would be an empty shell whose only job is to marshal a type it does not own. It would also contradict the project's stated preference against speculative structure.

**Never carve it; keep everything in `rules`.** Attractive because one context is simpler than two and the code shares types today. Rejected because it reproduces exactly the overload ADR-0015 had to unwind: `detection` carried visibility, detection, and an operator surface until the store forced a split. Rule evaluation and rule content have different data, different lifecycles, and different trust boundaries, and the second of those arrives on a known date.

**Carve at Phase 4 (import) instead of Phase 5.** Attractive because import is where foreign content and licence obligations first appear. Rejected because Phase 4 imports into the same compiled-in catalog and still persists nothing; the aggregate does not exist until #766 gives it storage. Carving at 4 would move the shell one phase earlier without moving the boundary.

**Make it a package convention rather than a context.** Attractive because it is free: keep `rules/internal/content/` and rely on review to police the seam. Rejected because `arch-go` enforces context boundaries and enforces nothing about intra-context packages, so the boundary would hold exactly as long as everyone remembered it. The trust boundary around untrusted operator content is not something to leave to memory.

## References

- Epic [#756](https://github.com/getvictor/fleet-edr/issues/756): declarative rule format, six phases.
- [#766](https://github.com/getvictor/fleet-edr/issues/766) runtime rule packs, the carve point. [#767](https://github.com/getvictor/fleet-edr/issues/767) authoring and validation. [#768](https://github.com/getvictor/fleet-edr/issues/768) pack versioning.
- [#757](https://github.com/getvictor/fleet-edr/issues/757) rule-file export, whose serialiser moves to `rulecontent` at the carve.
- [#765](https://github.com/getvictor/fleet-edr/issues/765) rule-author attribution, the Detection Rule License obligation.
- [0004](0004-modular-monolith-bounded-contexts.md) the original five contexts; [0015](0015-clickhouse-visibility-store.md) the carve-when-it-acquires-a-store precedent.
