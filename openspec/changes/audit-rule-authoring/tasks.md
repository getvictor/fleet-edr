# Tasks

- [ ] `rulecontent/api` publishes the authoring lifecycle as `Author`, so `rules` holds a port rather than reaching into another context's internals. The validator stays injected, so `rulecontent` still imports no other context's api and `arch-go.yml` is unchanged.
- [ ] Two new authorization actions, read and write, registered in the action list, the policy's action mirror, and the role grants. Read goes to admin and senior_analyst, write to admin, matching `detection_config`: authoring is a governed change to what the deployment detects, made by the same people from the same screen.
- [ ] Two new audit actions, one for a write and one for a deletion, recorded against the acting principal with the document and the operator's stated reason.
- [ ] A change with no stated reason is refused, so the audit trail cannot carry an empty governance field.
- [ ] Only a change that TOOK EFFECT is audited. A refused submission is not a mutation, and recording it as one would make the trail disagree with the corpus. Mutation-tested, since the absence of a row is exactly the assertion that passes by accident.
- [ ] A dry-run check reports what would be refused or warned about, changes nothing, and records no mutation.
- [ ] An unauthorized request is refused without disclosing whether the named document exists, since existence is itself information about what a deployment detects.
- [ ] The operator surface lives in the `rules` operator handler, which is the answer to the question ADR-0021 deferred to this issue. Reasoning in the proposal.
- [ ] Real-tool QA against the dev server: authorize, write, read back, delete, and confirm the audit rows, rather than asserting the same thing twice in Go.
