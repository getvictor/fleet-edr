# A wildcard pattern is compiled, not re-scanned

## Why

The Sigma wildcard matcher walks the value and the pattern together, backtracking whenever a `*` has to swallow one more character. That is O(value x pattern): a star followed by a long literal run re-tries that run at every offset of the value.

An attacker controls the event value. They do not control the pattern, so the exposure is not the synthetic worst case but what a pattern the corpus already ships can be driven to, and a 4 KB value built to keep almost-matching a real macOS rule cost 43.9us for a single field test against a typical 546ns. That runs per event, per rule, per field.

## Why now, and what changed since the issue was filed

The issue said no shipped rule reaches this path. That is still true: no detection block ships a Sigma wildcard today, and the two patterns that look like wildcards are `|re` regexps, which Go's regexp engine evaluates. So there is no production exposure to fix, and this is entirely about what comes next.

What comes next is the point. #764 imports 55 rules, of which 31 of the 69 macOS corpus rules use wildcards in plain values, and #767 lets operators author patterns, at which point the pattern shape stops being something reviewed. Either one turns a bounded annoyance into an ingestion-stall vector, and both are the next things in this epic.

## What changes

A pattern is split at load into the literal segments between its stars. Sigma's `*` matches any run, so those segments must simply appear in order: the first anchored at the start of the value, the last at the end, the rest found left to right. Taking the leftmost occurrence of each middle segment is optimal, because it leaves the most room for the ones after it, so no choice is ever revisited and the backtracking disappears.

Measured on the same inputs, 20,000 iterations, all zero-allocation:

| shape | reference | compiled |
| --- | --- | --- |
| typical corpus pattern (`*/MacOS/*`) | 546ns | **22.5ns** |
| corpus pattern, suffix anchor rejects | 43.9us | 18.7ns |
| corpus pattern, past the anchor | 43.9us | **6.5us** |
| synthetic worst case (`*` + 64 literals) | 1.52ms | **236ns** |
| `?` in a middle segment | 829us | 326us |

The third row is the honest figure for the attacker-driven case. The second rejects on the suffix anchor before searching anything, which is a real and common outcome, but quoting it would compare a full scan against an early exit.

## What it does not fix

A middle segment carrying `?` cannot use a substring search, so it still walks candidate offsets. It is 2.5x faster than the scan it replaces and it is the shape with the most left in it. Reaching it needs a pattern chosen to be pathological rather than a value, which today means a rule author, so it belongs with #767 rather than here.

## The gate

The backtracking scan is kept, frozen, as the reference implementation in the test file, and a property compares the two over patterns drawn from a metacharacter-dense alphabet with values built from the pattern so that matches and near-misses are common rather than vanishingly rare. Every mutation of the compiled matcher fails it.

## Impact

No change to what any rule matches. The matcher answers identically and does so faster, including 24x faster on the shape the corpus actually contains.
