# Tasks

## 1. Compose instead of replacing

- [x] 1.1 Give a finding risk modifiers: what a condition adds, and the techniques it implies, in one entry so the two cannot drift.
- [x] 1.2 Put a risk scale behind the bands, so an escalation can be a delta that composes with any base.
- [x] 1.3 Apply the operator's setting to the base, then the modifiers, and clamp.
- [x] 1.4 Stamp a modifier's techniques AFTER a finding's own are resolved, or a rule that declares a set for every finding loses it in favour of the modifier's.
- [x] 1.5 Convert `dns_c2_beacon`'s DGA escalation, choosing the delta so the untuned rule reports what it always did.
- [x] 1.6 Compose in the fixture-replay harness too. It evaluates rules directly, so it would otherwise pin a base no operator ever sees and go green if the composition were removed.

## 2. Tests

- [x] 2.1 Assert the ORDERING across every base, not a table of bands. Bands would pass against an implementation that collapsed the two populations, as long as it collapsed them to the values written down.
- [x] 2.2 Pin that an untuned deployment sees exactly the severities it did before.
- [x] 2.3 Pin both ends of the clamp and the band boundaries, since every delta is judged against them.
- [x] 2.4 Drive the ENGINE for the ordering, since what could be wrong there is the order the setting and the modifiers are applied in.
- [x] 2.5 Drive the whole path to the persisted alert for the techniques, which is the only place they become observable. A unit test on the union helper passed with the engine's call to it removed.
- [x] 2.6 Mutation-test: the setting as last word, no composition, a delta turned into a destination, no technique stamping, and stamping before the fallback.
