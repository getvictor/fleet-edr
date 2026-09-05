# Let operators author rule content, safely

## Why

#766 made rule content storage-backed, so the corpus a deployment runs is now data rather than a build artifact. Nothing yet writes to it but the seed. Issue #767 is the phase where that storage gains an operator-facing write path, and with it the property that makes this phase different in kind from the ones before it: **rule content becomes untrusted input.**

The CRUD is the small part. The substance is what happens between "an operator submitted a rule" and "the fleet evaluates it".

## What already exists, which narrows this considerably

Two of the issue's three acceptance criteria are already met by work that landed in earlier phases, and re-implementing either would be the semantic duplication this codebase is most prone to:

- **A catastrophic-backtracking regex cannot stall evaluation.** Go's `regexp` is RE2, so catastrophic backtracking is not expressible; the glob matcher (#853) compiles to anchored segments with no backtracking at all; and #852 refuses a pattern whose estimated cost exceeds `maxValueCost`, or a field whose values together exceed `maxFieldCost`, naming the field to fix. That same field bound caps how many values a field may carry, which is the issue's "bounded list sizes".
- **A rule exceeding its evaluation budget is disabled and reported, not silently retried.** #836 skips a rule that repeatedly overruns `maxRuleEvalNs` on the replica that measured it, names it in logs and a counter, and leaves its configured mode alone.

So this change builds the third criterion, and the path that makes the first two reachable from the authoring surface rather than only from the loader.

## What changes

- Rule content gains a per-document write path: create, replace, delete. Each writes the document and the corpus version in one transaction, so a replica polling for change never sees a version that promises content it cannot read.
- Every write is validated first, **by the loader itself** rather than by a second parser written to agree with it. A document that the corpus loader would reject is refused at authoring time, with the loader's own reason.
Not here, and deliberately: the operator-facing HTTP surface, its authorization, the audit of every mutation, and the warning for a detection with no discriminating predicate. Those are the consumer half and they follow in the next change, which keeps this one at the size the repo aims for and sequences the producer first. Nothing calls the authoring service until then, exactly as #766 shipped `Replace` before anything replaced a corpus.

## Where the seam falls, which ADR-0021 deferred to this issue

ADR-0021 left one question open: whether the operator-facing HTTP surface for authoring lives in `rulecontent` or stays in the `rules` operator handler, "depending on how much the authoring UI shares with the tuning UI, which #767 will make apparent."

It is now apparent, and the answer is **the `rules` operator handler**. Authoring shares the tuning surface's authz chokepoint, its audit recorder, its handler shell, and its place in the UI: an operator authors a rule and then tunes its mode from the same table. Putting the HTTP surface in `rulecontent` would mean a second operator handler, a second authz wiring, and a duplicate of the audit plumbing, to serve a screen that sits beside the one that already exists.

The **content** half stays where ADR-0021 put it. `rulecontent` owns the documents, their version, the write transaction, and the authoring lifecycle. What crosses into `rules` is the HTTP surface and the validator, and the validator crosses by INVERSION rather than by import: `rulecontent/api` declares the port it needs, and `rules` supplies the implementation that runs the loader. `rulecontent` still imports no other context's api, and `arch-go.yml` is unchanged, which is the check that the seam held.

## Validation runs the real loader, not a copy

The validator hands the submitted document to `catalog.LoadCorpus` over a single-document filesystem. This is the same function the corpus load runs and the same one CI's corpus test runs, so "valid" means exactly "this deployment will load it", with no second implementation to drift.

It also means the cost bounds, the unsupported-Sigma rejections, the duplicate-identity check, and the condition-depth limit are all enforced at authoring time for free, because they are the loader's behaviour rather than something this change re-states.
