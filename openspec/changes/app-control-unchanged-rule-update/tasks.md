# Tasks

- [x] Lock the rule row at the update's lookup, so a zero affected-row count means nothing changed rather than a concurrent delete.
- [x] Report from the store whether the update changed anything, and advance the policy version only when it did.
- [x] Skip the snapshot fan-out and the audit event for an update that changed nothing.
- [x] Integration test: an unchanged PATCH returns 200 with the rule, leaves the version, enqueues nothing and records no audit event; a PATCH that changes one of its fields is still a mutation.
