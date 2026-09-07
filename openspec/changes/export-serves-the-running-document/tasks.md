# Tasks

## 1. Let a rule answer for its own document

- [x] 1.1 Add an optional `SourceCarrier` interface and `SourceOf`, so a rule that came from a document hands it back and one that did not is distinguishable from one with an empty document.
- [x] 1.2 Implement it on the imported rule, returning the bytes it was loaded from.
- [x] 1.3 Delete the identifier-to-embedded-corpus lookup and scrub the comments naming it.

## 2. Resolve the export from the active rule set

- [x] 2.1 Give the service a lookup returning a rule AND its metadata from one snapshot, and have the export route use it, so the document served and the metadata describing it cannot come from different generations.
- [x] 2.2 Share one metadata projection between that lookup and the catalog listing, so the export cannot publish metadata that differs from what the catalog shows.
- [x] 2.7 Scope the guarantee to the rule set in FORCE, which is the catalog's generation. Installing a set replaces the catalog's copy before rebuilding what evaluation derives from it, and in-flight evaluations finish on their own generation, so a claim about what detection is evaluating would be stronger than the implementation makes.
- [x] 2.3 Re-derive the generated pack's "ours or not" partition from attribution rather than from the deleted lookup, and verify the generated pack is byte-identical.
- [x] 2.5 Require rule-content read authorization for a document an operator wrote, and only for that. The route used to serve only the product's own content, so the catalog's own gate covered it; gating every rule instead would withdraw export of the shipped rules from roles that already read them on the catalog.
- [x] 2.6 Set `Cache-Control: no-store`, since the URL now answers what is running and the answer changes on a reload.
- [x] 2.4 Set `X-Content-Type-Options: nosniff` on the response. This is the first version of the route whose body is not fixed at build time, so a browser deciding a stored document looks like HTML is now reachable.

## 3. Tests

- [x] 3.1 Regression: an operator's document stored under a shipped rule's stem exports as their bytes, and does not carry the shipped document's content.
- [x] 3.2 Mutation-test: restoring the embedded-corpus lookup fails the regression test.
- [x] 3.3 Keep the vendored case pinned, so the fix is not "stop serving documents", and give it an INDEPENDENT oracle: read the expected bytes off the embedded corpus, since taking them from the same rule the handler serves would pass against a handler serving the wrong document.
- [x] 3.4 Guard the single-generation property with a fake whose two reads permanently disagree, in BOTH directions: a rule the stale listing names and the current set has dropped must be a 404 rather than a rendered stale answer, and one the current set runs and the stale listing omits must still be served. One direction alone is satisfied by a handler that answers 404 to everything.
- [x] 3.5 Mutation-test that guard by reintroducing the List pairing, since the first version of the test asserted the wrong thing and the mutant survived it.
- [x] 3.6 Exercise the single-snapshot lookup WHILE the set is being replaced. With one generation installed the two reads agree however they were obtained, so the non-concurrent test cannot fail; alternating generations that share a rule id and differ in title makes a split pair observable.
