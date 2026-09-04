# Tasks

## 1. Bound the cost of an authored pattern (this PR)

- [x] One cost model, bounded per pattern AND per field. Independent per-value limits do not bound what an event pays: 512
      individually legal values on one field measured at 100ms per event.
- [x] A wildcard pattern's unit is the LENGTH of a segment with a star on either side, not its `?` count. 1024 literal characters
      cost 1.41ms, 1024 `?` cost 4.10ms; bounding one and not the other left half the cost open.
- [x] A regular expression's unit is its compiled program size, asked of `regexp/syntax` rather than guessed from the source.
      `(abcd){1000}` is 12 bytes and 6002 instructions.
- [x] Adjacent stars collapse at compile time rather than being refused, since `**` means what `*` means. Measured at 19ns for two
      and 40us for 8192 before the collapse.
- [x] Every value is charged a base cost for the comparison it always pays, so ONE budget bounds both how complex a field's
      patterns are and how many there are. Review found the hole: literals and end-anchored patterns estimated at zero let an
      unbounded list pass while match still walked all of it, measured at 309us per event for 65536 of them.
- [x] Refusals name the field, the limit, and whether one pattern or the field's total reached it.
- [x] The bounds sit in the one function every pattern passes through, so validation and load cannot disagree.
- [x] Every vendored rule still imports, 66 with the same 3 refusals, and a rule refused for cost does not stop its siblings
      loading (asserted at the loader, which is the only level that can show it).
- [x] Mutation-tested five ways: the `?`-only unit, the missing per-field sum, source-length regex bounding, the star collapse, and
      the anchored-segment exemption. Source-length bounding SURVIVED the first attempt, because the test asserted only that a
      nested-repeat pattern errored and Go's own parser refuses that; the case now uses a pattern Go accepts.

## Deliberately not bounded, with the measurement

- Star count with non-empty segments. Flat at 119ns for one and 129ns for 256.
- Nested repeats in `|re`. Go's parser refuses them, and a test records that this bound is not what does it.

## 2. Per-rule evaluation budget (next PR)

- [ ] Measure per-rule evaluation time; a rule over budget is disabled and surfaced rather than slowing every batch.
- [ ] Must NOT present as a retryable batch failure, or the batch retries forever on the rule that is too slow, which is #836's failure mode again.
