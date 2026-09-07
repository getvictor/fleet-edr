# Record where a rule document came from

## Why

Two problems share one cause, and neither is fixable without the other.

**An operator's own rule is credited to SigmaHQ (#874).** Every document loaded from storage becomes an `importedRule`, whose origin is hardcoded to the upstream project. That was correct while the corpus could only contain vendored content. #873 gave the corpus a write path and #875 gave operators a way to use it, so "stored means imported" stopped being true and nothing said so. It matters beyond a wrong label: the credit is the mechanism honouring the Detection Rule License, so it misstates the licensing of the operator's own work, in the surface built to get attribution right.

**A product upgrade never refreshes the vendored rules (#768).** `SeedFrom` is the only writer of vendored content and it goes through `ReplaceIfEmpty`, which writes only into an empty corpus. So a deployment seeds once, on its first boot, and then keeps that generation forever. New detections shipped in later releases do not reach it. That is the "upgrading a pack" this phase exists to make possible, and it cannot be done safely without knowing which documents came from the pack: replacing everything would destroy an operator's authored rules.

Both need the same missing fact, which is where a document came from.

## What changes

A document records its **source**: shipped with the product, or written by an operator.

Provenance is recorded rather than derived, and that is the load-bearing decision. #873 deliberately established that a rule's identity is its file STEM rather than its path, and loosened the load to walk the whole stored set so authored content need not live under `imported/`. Deriving provenance from a path prefix would contradict that and would be guessable by an operator who chooses their own paths. What the store knows, and only the store knows, is how a document ARRIVED: through the seed, or through the authoring surface.

The corpus also gains a **pack identity**: a digest over the vendored documents. It changes exactly when the shipped content changes, needs no manual version bump, and makes "is this deployment running the pack in this build" a comparison rather than a judgement.

## What this does NOT do

Upgrade or roll anything back. That is the next change, and it needs this one first: an upgrade replaces the vendored half and must leave the authored half alone, which is not expressible until the two are distinguishable.

## Attribution follows the recorded source

A vendored rule keeps crediting SigmaHQ and its author exactly as today. An authored rule is credited to the deployment that wrote it, not to an upstream project it has nothing to do with, and its alerts stop carrying a Detection Rule License attribution they were never under.
