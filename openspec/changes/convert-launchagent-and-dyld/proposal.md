# Convert the remaining reachable rules to Sigma detection blocks

## Why

#793 built the machinery and converted one rule. This converts the other two that are reachable today: `persistence_launchagent` and `dyld_insert`. (`shell_from_office` and `sudoers_tamper` stay in Go until the enrichments in #771 and #772 land, as #761 records.)

## What changes

Both rules move their logic into a `detection:` block, and both lose their `x-engine.params`, their `x-engine.algorithm`, and their Go matchers. Three of the ten algorithm names are now gone from the engine, which is the point of the exercise: the Go surface shrinks to the rules that genuinely need the process graph.

Each detection matches the **complete** predicate its Go rule did, including the binary. That is a direct consequence of #793's review, where the property compared only the argv half of the keychain rule and left the binary check outside the gate. Both properties here vary the executable path from the start, and the mutation sweep covers widening or case-folding either half.

## An alert still names what fired

A converted rule reads back the values its detection matched on, through the same computed fields, so the alert text does not drift from the match. `persistence_launchagent` names the subcommand and the plist it registered; `dyld_insert` names the DYLD variable and, as before, **withholds its value**, because the injected dylib path is attacker-chosen content in an operator-facing string.

## One observable change, in `persistence_launchagent`

Calling this behaviour-neutral would be wrong, and review caught the claim. `Subcommand` treats an empty token as the verb rather than skipping it, so `launchctl "" load x.plist` no longer produces a finding where the Go matcher did. The correction was introduced with the field in #790 and reaches this rule here, because this is where the rule starts reading it.

It is a narrowing, never a widening: the matcher skipped the empty token only because it used `""` as its not-found sentinel and could not record an empty verb, and `launchctl` would reject that verb and load nothing. Triage should expect one fewer finding shape, not a different one. The equivalence property requires that any divergence be exactly this shape AND always in the direction of removing findings, so nothing else can hide behind it.

## Impact

No other behaviour change, and none that expands what either rule alerts on. Both rules' test files and fixtures are untouched: 21 of their existing tests pass against the Sigma implementations unchanged, and the pre-conversion matchers are frozen in the equivalence properties as the oracles, as literal copies rather than references to the live symbols.
