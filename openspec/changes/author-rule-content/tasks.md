# Tasks

- [x] Rule content gains a per-document write path: create or replace, and delete. Each writes the document and bumps the corpus version in ONE transaction, so a replica polling the version never learns of a change whose content it cannot yet read.
- [x] Deleting a path the corpus does not have reports not-found rather than success, so an operator learns whether they deleted the rule they meant.
- [ ] A failed write leaves both the document and the version untouched, pinned by a test that fails the commit rather than by inspection.
- [x] Validation runs `catalog.LoadCorpus`, the same loader the corpus load and the CI corpus test run, over the WHOLE document set the write would produce. A rule's identity is its file stem and a duplicate identity refuses the entire corpus, so validating the submitted document alone would accept the one write that can take a deployment's rule set down to its embedded copy.
- [x] The validator reaches `rulecontent` by INVERSION, not import: `rulecontent/api` declares the port, `rules` supplies the implementation, `cmd` wires it. `arch-go.yml` is unchanged, which is the check that the seam held.
- [x] A refused document is not written and does not move the corpus version, and the refusal carries the loader's own reason rather than a rephrasing.
- [x] Mutation-tested: dropping the version bump, dropping the validator call, treating a warning as a refusal, and auditing a refusal each fail a test.

## Not built here, and why

- **Bounded regex evaluation and bounded list sizes** are already enforced by #852 at load: a pattern above `maxValueCost` and a field whose values together exceed `maxFieldCost` are both refused, naming the field. Go's `regexp` is RE2 and the glob matcher compiles to anchored segments, so catastrophic backtracking is not expressible in the first place. Re-implementing any of this in the authoring path would be a second copy to keep in step.
- **Bounded per-rule evaluation time with a rule that exceeds it disabled and surfaced** is already #836: a rule that repeatedly overruns `maxRuleEvalNs` is skipped on the replica that measured it, named in the logs and a counter, with its configured mode left alone.

Both are reachable from the authoring surface for free, because validation runs the loader rather than a copy of it.

## Deferred to the consumer half

The operator HTTP surface, its authorization, the audit of every mutation, and the warning for a detection with no discriminating predicate. Splitting there keeps this change at the size the repo aims for and sequences the producer first, as #766 did when it shipped `Replace` before anything replaced a corpus.

ADR-0021 deferred one question to this issue: whether that HTTP surface lives in `rulecontent` or in the `rules` operator handler. The answer is the `rules` operator handler, and the reasoning is in the proposal, but the code for it lands with the consumer half.
