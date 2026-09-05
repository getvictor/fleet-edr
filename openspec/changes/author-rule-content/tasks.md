# Tasks

- [ ] Rule content gains a per-document write path: create or replace, and delete. Each writes the document and bumps the corpus version in ONE transaction, so a replica polling the version never learns of a change whose content it cannot yet read.
- [ ] Deleting a path the corpus does not have reports not-found rather than success, so an operator learns whether they deleted the rule they meant.
- [ ] A failed write leaves both the document and the version untouched, pinned by a test that fails the commit rather than by inspection.
- [ ] Validation runs `catalog.LoadCorpus`, the same loader the corpus load and the CI corpus test run, over a single-document filesystem. No second notion of validity exists to drift from the first.
- [ ] The validator reaches `rulecontent` by INVERSION, not import: `rulecontent/api` declares the port, `rules` supplies the implementation, `cmd` wires it. `arch-go.yml` is unchanged, which is the check that the seam held.
- [ ] A refused document is not written and does not move the corpus version, and the refusal carries the loader's own reason rather than a rephrasing.
- [ ] A detection with no discriminating predicate is WARNED about and accepted, because a broad hunting rule is legitimate and refusing it substitutes our judgement for the operator's.
- [ ] Every mutation that took effect is audited against the acting principal, naming the document, distinguishing write from delete. A refusal is not audited as a mutation, since the corpus did not change.
- [ ] The operator HTTP surface lives in the `rules` operator handler, answering the question ADR-0021 deferred to this issue. Recorded in the proposal with the reasoning: authoring shares the tuning surface's authz chokepoint, audit recorder, handler shell, and screen.
- [ ] Mutation-tested: dropping the version bump, dropping the validator call, treating a warning as a refusal, and auditing a refusal each fail a test.

## Not built here, and why

- **Bounded regex evaluation and bounded list sizes** are already enforced by #852 at load: a pattern above `maxValueCost` and a field whose values together exceed `maxFieldCost` are both refused, naming the field. Go's `regexp` is RE2 and the glob matcher compiles to anchored segments, so catastrophic backtracking is not expressible in the first place. Re-implementing any of this in the authoring path would be a second copy to keep in step.
- **Bounded per-rule evaluation time with a rule that exceeds it disabled and surfaced** is already #836: a rule that repeatedly overruns `maxRuleEvalNs` is skipped on the replica that measured it, named in the logs and a counter, with its configured mode left alone.

Both are reachable from the authoring surface for free, because validation runs the loader rather than a copy of it.
