# Tasks

- [x] Pack loader compiles and checks `detection:` blocks when the catalog is built
- [x] Rule files carry an authored detection block that regeneration re-emits verbatim
- [x] `type` and `portable` derived from the rule rather than hardcoded
- [x] `credential_keychain_dump` converted; its Go matcher, params and algorithm removed
- [x] The pre-conversion matcher frozen as the equivalence oracle
- [ ] Convert `persistence_launchagent` and `dyld_insert` (#761)
