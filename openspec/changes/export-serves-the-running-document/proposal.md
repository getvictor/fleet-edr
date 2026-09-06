# Exporting a rule returns the document the deployment is running

## Why

Exporting a rule an operator had overwritten returned the shipped file instead of theirs.

A rule's identity is its file STEM and not its path (#873), so an operator who stores their own version of a shipped detection keeps that detection's identifier, and from then on the rule the deployment evaluates is theirs. The export path did not resolve the rule that way: it looked the identifier up in the corpus embedded in the BUILD, found the shipped document still sitting under that stem, and handed back content the deployment was not running and the operator had not written.

The export is the artifact an operator saves, reads, diffs, and hands to another tool, so wrong bytes there are wrong everywhere downstream. It is also the surface someone reaches for precisely when they want to confirm what is running.

## What Changes

- A rule answers for its own document, through an optional `SourceCarrier` interface, instead of an identifier being resolved against the embedded corpus.
- The export route reads the ACTIVE rule set, so it serves what the deployment evaluates: upstream's file for a vendored rule, and the operator's own file for one they wrote.
- The classifier that conflated "came from a document" with "is upstream's" is removed. Its other callers ask the second question, which is attribution, and now use the attribution the listing already carries.

## Impact

- Affected specs: `server-detection-rules-engine`
- Affected code: `server/rules/api/types.go`, `server/rules/internal/catalog/imported.go`, `server/rules/internal/operator/handler.go`, `server/rules/bootstrap/bootstrap.go`
