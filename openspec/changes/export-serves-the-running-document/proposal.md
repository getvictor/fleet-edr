# Exporting a rule returns the document the deployment is running

## Why

Exporting a rule an operator had overwritten returned the shipped file instead of theirs.

A rule's identity is its file STEM and not its path (#873), so an operator who stores their own version of a shipped detection keeps that detection's identifier, and from then on the rule the deployment evaluates is theirs. The export path did not resolve the rule that way: it looked the identifier up in the corpus embedded in the BUILD, found the shipped document still sitting under that stem, and handed back content the deployment was not running and the operator had not written.

The export is the artifact an operator saves, reads, diffs, and hands to another tool, so wrong bytes there are wrong everywhere downstream. It is also the surface someone reaches for precisely when they want to confirm what is running.

## What changes

- A rule answers for its own document, through an optional `SourceCarrier` interface, instead of an identifier being resolved against the embedded corpus.
- The export route resolves the rule and its metadata from ONE snapshot of the rule set in force, so it serves what the deployment is running: upstream's file for a vendored rule, and the operator's own file for one they wrote. "In force" means the catalog's generation, which during a content reload is briefly ahead of the one detection is evaluating; the export follows the catalog so that a rule read alongside it agrees, and that window is the one `installRuleSet` already documents rather than a new one. One snapshot rather than two reads, because a reload landing between them would leave the route rendering metadata for a rule the deployment no longer runs, and for a rule loaded from a document that renders to nothing.
- That lookup and the catalog listing share one metadata projection, so the export cannot publish metadata differing from what the catalog shows.
- The classifier that conflated "came from a document" with "is upstream's" is removed. Its other callers ask the second question, which is attribution, and now use the attribution the listing already carries.
- Exporting a document an operator WROTE now requires the authorization that reading rule content requires; exporting a shipped rule does not. The route could only return the product's own content before this, so the catalog's own gate covered it. Gating every rule instead would withdraw export of the shipped rules from roles that already read them on the catalog.
- The response carries `Cache-Control: no-store`, because the URL now answers what is running and that answer changes on a reload.
- The response carries `X-Content-Type-Options: nosniff`. This is the first version of the route whose body is not fixed at build time, so a browser overruling the declared type on content an operator stored is now a reachable path rather than a hypothetical one.

## Impact

- Affected specs: `server-detection-rules-engine`
- Affected code: `server/rules/api/types.go`, `server/rules/internal/catalog/imported.go`, `server/rules/internal/service/service.go`, `server/rules/internal/operator/handler.go`, `server/rules/bootstrap/bootstrap.go`
