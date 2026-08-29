# Rule pack

The pack moved. One declarative rule file per registered detection now lives at [`server/rules/internal/catalog/pack/`](../../server/rules/internal/catalog/pack), inside the package that reads it.

## Why it moved

Phase 1 generated these files and nothing read them, so `docs/` was a reasonable home. From Phase 2 the rules read their own parameters out of them at boot, and a `go:embed` pattern cannot contain `..`, so a package under `server/rules/` cannot embed a directory at the repository root.

Keeping the canonical copy here and generating a second one next to the code was the obvious workaround and the wrong one: that is the arrangement in issue #781, where the embedded OpenAPI spec drifted 49 lines from its canonical source because the `go:generate` that syncs them is wired to nothing. One canonical location, owned by the code that reads it, has no such failure mode.

## Working with the pack

Refresh it with `task docs:rule-pack`. A stale or missing file fails CI, and regeneration removes files for rules that are no longer registered.

Everything in a rule file is generated from the rule's Go documentation **except `x-engine.params`**, which the rules read at boot and which is therefore authored by hand. Regeneration re-emits an existing params block verbatim, comments included.

## Where a value lives

What reads a value decides which file holds it.

A value only one rule matches against is that rule's parameter, under `x-engine.params` in its own file. A value more than one rule matches against lives in `pack/lists.yml`, defined once and read by every consumer; copying it into each rule's file would leave nothing keeping the copies equal, which is weaker than the single definition it replaced. `lists.yml` is authored rather than generated, and regeneration leaves it alone.

Some values stay in Go on purpose. A parameter that bounds **retrieval** rather than the decision (the ingest and clock-skew pads, the ancestor-walk and descendant caps, the DNS port) is not exposed, because widening it changes no finding and narrowing it causes silent false negatives: no setting improves detection, so the knob would be all downside.
