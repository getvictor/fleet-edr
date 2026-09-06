# Tasks

## 1. Let a rule answer for its own document

- [x] 1.1 Add an optional `SourceCarrier` interface and `SourceOf`, so a rule that came from a document hands it back and one that did not is distinguishable from one with an empty document.
- [x] 1.2 Implement it on the imported rule, returning the bytes it was loaded from.
- [x] 1.3 Delete the identifier-to-embedded-corpus lookup and scrub the comments naming it.

## 2. Resolve the export from the active rule set

- [x] 2.1 Give the service a lookup returning a rule AND its metadata from one snapshot, and have the export route use it, so the document served and the metadata describing it cannot come from different generations.
- [x] 2.3 Share one metadata projection between that lookup and the catalog listing, so the export cannot publish metadata that differs from what the catalog shows.
- [x] 2.2 Re-derive the generated pack's "ours or not" partition from attribution rather than from the deleted lookup, and verify the generated pack is byte-identical.

## 3. Tests

- [x] 3.1 Regression: an operator's document stored under a shipped rule's stem exports as their bytes, and does not carry the shipped document's content.
- [x] 3.2 Mutation-test: restoring the embedded-corpus lookup fails the regression test.
- [x] 3.3 Keep the vendored case pinned, so the fix is not "stop serving documents", and give it an INDEPENDENT oracle: read the expected bytes off the embedded corpus, since taking them from the same rule the handler serves would pass against a handler serving the wrong document.
