# Tasks

- [x] Read the rule under a row lock at the update's lookup and compare the request's fields with it, independent of the driver's affected-row mode.
- [x] Report from the store whether the update changed anything, and advance the policy version only when it did.
- [x] Skip the snapshot fan-out and the audit event for an update that changed nothing.
- [x] Integration test: an unchanged PATCH returns 200 with the rule, leaves the version, enqueues nothing and records no audit event; a PATCH that changes one of its fields is still a mutation.
- [x] Restate the rule lifecycle audit requirement with the exception for an update that changes nothing.
- [x] Unit test the field comparison, including nullable strings and expiry precision.
