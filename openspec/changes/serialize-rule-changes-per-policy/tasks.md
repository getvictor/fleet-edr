# Tasks

- [x] Reproduce both deadlock shapes against a real MySQL before changing anything, so the tests are known not to be vacuous.
- [x] Take the policy row lock first in create, update and delete, as bulk upsert already does.
- [x] Generalise the lock helper, since the ordering belongs to the store rather than to bulk upsert.
- [x] Resolve a rule's policy without a lock, and say why that cannot go stale.
- [ ] Mutation-check each reordering separately: restoring any one of the three old orders must fail a test.
- [ ] Confirm the missing-policy and missing-rule answers are unchanged.
