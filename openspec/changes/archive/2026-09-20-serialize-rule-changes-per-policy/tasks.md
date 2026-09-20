# Tasks

- [x] Reproduce both deadlock shapes against a real MySQL before changing anything, so the tests are known not to be vacuous.
- [x] Take the policy row lock first in create, update and delete, as bulk upsert already does.
- [x] Generalise the lock helper, since the ordering belongs to the store rather than to bulk upsert.
- [x] Resolve a rule's policy without a lock, and say why that cannot go stale.
- [x] Mutation-check each reordering separately: restoring any one of the three old orders must fail a test.
- [x] Confirm the missing-policy and missing-rule answers are unchanged.
- [x] Take the same lock in the demo seeder, which writes the same two rows against a server that is already serving.
- [x] Pin the wait itself, so the lock cannot be removed without a test noticing, and keep a database failure distinct from an absence.
