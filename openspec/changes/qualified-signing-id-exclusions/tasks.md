# Tasks

- [x] Compose the matched candidate from the parent's signature, qualified by team or by platform, with an ad-hoc parent composing to nothing.
- [x] Use it at the shell-chain parent exclusion site instead of the bare identifier.
- [x] Refuse a bare value at the create API, naming both accepted forms, wrapping both the invalid-request error and the specific one.
- [x] Tests for the ad-hoc bypass, the platform form, the team form, and the refusal; mutation-check each.
- [x] Correct the documentation that told operators to avoid `signing_id`.
- [x] Explain the form in the exclusion editor, where the operator types the value.
- [x] Upgrade note: existing bare exclusions have stopped suppressing and need rewriting.
- [ ] Confirm on a VM that an ad-hoc binary claiming an excluded identifier still produces a finding.
