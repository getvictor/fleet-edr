# Tasks

- [ ] Return the parent's whole image from the inherited-image lookup, not just its path, in both the store query and the batch overlay.
- [ ] Seed a fork row's `code_signing`, `sha256` and `cdhash` from it.
- [ ] Confirm an exec still overwrites all three, so no inherited identity survives an exec.
- [ ] Tests: a forked child carries its parent's identity, resolved from the same image the path came from; an unsigned parent yields none; an exec replaces it.
- [ ] A rules-level test that a `team_id` exclusion suppresses a chain whose non-shell parent is a fork-only child of a signed binary.
- [ ] Mutation-check the inheritance itself, not only the lookup: dropping each field from the fork insert must fail a test.
- [ ] VM QA on edr-dev: confirm a fresh `sshd-session` row carries a signature, and use it to finish the `platform:` qualifier proof that #1024 could not complete.
