# A rule is invoked only for the events it consumes

## Why

`Engine.Evaluate` invokes every registered rule for every batch. The only prefilter is platform, so each rule then re-filters the same batch itself, and the overwhelming majority discard it on their first line with `if evt.EventType != "exec" { return nil }`.

At twelve rules that is affordable. #764 brings roughly sixty-seven, and the cross-platform corpus implies far more. The cost of retrofitting dispatch grows with the catalog: doing it now means twelve rules to verify against a before-and-after baseline, rather than hundreds with no baseline to check against.

## What the telemetry says

Measured over 2.55M events in the dev corpus, the waste is not theoretical:

| Event type | Share of events | Rules consuming it |
| --- | --- | --- |
| `network_connect` | 36.8% | 2 |
| `exec` | 26.6% | 8 |
| `fork` + `exit` | 28.0% | **0** |
| `dns_query` | 8.6% | 1 |
| `open`, `btm_launch_item_add`, `sensor_provider_transition`, `sensor_recovery_failed` | 52 events in 2.55M | 4 |

Over a quarter of all telemetry is consumed by no rule at all. Four of the twelve rules read event types amounting to 0.002% of the corpus, and are invoked on every batch regardless.

## What changes

The engine builds an index from event type to the rules that consume it, and invokes a rule only when the batch carries a type it declares. The rule still receives the **whole** batch: the declaration is a trigger filter, not a batch filter, because a rule triggered by one type routinely reads another from the same batch. `suspicious_exec` triggers on a `network_connect` and reaches back for the `exec` that made it.

The platform check moves ahead of the per-rule span, alongside the index check. A rule left with nothing to evaluate did not run, and a span for it reports work that never happened.

## One index key, not two

The issue specifies two derivations: `logsource.category` for `sigma` rules, `x-engine.event_types` for `graph` rules. All twelve registered rules already declare `Doc().EventTypes`, and that is the only source correct for every one of them:

- `dns_c2_beacon` declares category `network_connection` but consumes `network_connect`, `dns_query` and `exec`. Deriving from category would silently under-dispatch it, which the issue itself warns about.
- `privilege_launchd_plist_write` and `sensor_tamper` carry categories (`btm_launch_item_add`, `sensor_provider_transition`) that are not Sigma categories at all, so there is nothing to map.

The category path exists for imported rules (#763), which have no Go `Doc()`. Those should synthesise their `EventTypes` in the importer, keeping Sigma taxonomy inside the rules context rather than teaching the detection engine to read it (ADR-0004). One path now; #763 fills the contract rather than adding a second path here.

## Failing open

A rule declaring no event types is invoked for every batch. The two ways of being wrong are not symmetric: invoking a rule that had nothing to do costs time, while skipping one that did have something to do loses a detection silently, with no error and no alert. Dispatch is an optimisation, so it takes the safe direction. A catalog guard test asserts every shipped rule declares, so nothing forfeits the optimisation by accident.

## The gate

Dispatch is an optimisation, so any behaviour change is a bug. Every existing engine test passes unchanged except one, which asserted that a rule handed an empty batch still opens a span; it now feeds an event, because that is the behaviour this change deliberately alters.

Measured on a synthetic catalog, for a batch of a type one rule consumes:

| Catalog | Before | After |
| --- | --- | --- |
| 12 rules | 7,370 ns, 109 allocs | 312 ns, 9 allocs |
| 100 rules | 43,389 ns, 901 allocs | 308 ns, 9 allocs |
| 500 rules | 157,039 ns, 4,501 allocs | 267 ns, 9 allocs |

Linear before, flat after.

## Impact

No change to what fires. A rule that is skipped could not have produced a finding from that batch, which is asserted for every shipped rule.
