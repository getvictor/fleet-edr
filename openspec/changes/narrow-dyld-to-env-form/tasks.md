# Tasks

- [x] The computed field stops reporting `argv[0]` for a non-`env` binary, since no agent can produce that shape.
- [x] The rule's summary, description and limitations say it detects the `env` form only, and say plainly that the shell form is not detected and never was.
- [x] Fixtures that used the shell form as a convenience are converted to the `env` form, including the corpus fixture, which is renamed so its name still describes it.
- [x] The equivalence property asserts the new divergence by shape: a non-`env` invocation whose `argv[0]` is an assignment is a finding the conversion REMOVES. Mutation-tested on 8 seeds, both the carve-out and its predicate.
- [x] Mutation-tested: restoring the branch is caught by six tests, so the narrowing is pinned rather than merely applied.
- [x] The rule pack and generated docs are regenerated from the rule's documentation.
