# Tasks

## 1. Bound the cost of an authored pattern (this PR)

- [ ] Bound `?` in a non-anchored segment, the residual #787 deferred here by name, measured at 27.6us to 4.10ms as the count grows.
- [ ] Bound `|re` source length, which is what bounds the compiled program that match cost tracks.
- [ ] Bound the number of values in one field test, which is the multiplier on both.
- [ ] Refusals name the field and the limit, as `ErrUnsupported` does elsewhere in this package.
- [ ] The bounds sit in the one function every pattern passes through, so the loader CI runs and the loader a publish runs cannot disagree.
- [ ] Every vendored rule still imports: a bound that refuses content we ship is set wrong.
- [ ] Mutation-tested: each bound removed, and each set one past the value the tests use.

## Deliberately not bounded, with the measurement

- Star count. Flat at 119ns for one star and 129ns for 256.
- Nested repeats in `|re`. Go's parser refuses them.

## 2. Per-rule evaluation budget (next PR)

- [ ] Measure per-rule evaluation time; a rule over budget is disabled and surfaced rather than slowing every batch.
- [ ] Must NOT present as a retryable batch failure, or the batch retries forever on the rule that is too slow, which is #836's failure mode again.
