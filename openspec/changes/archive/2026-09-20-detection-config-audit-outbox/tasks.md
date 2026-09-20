# Tasks

- [x] Move the audit outbox drain and encoding from rule authoring to a shared package, with rule content adapted to it.
- [x] Add `detection_config_audit_outbox` (migration 00008) with held entries.
- [x] Write exclusion, rule setting and watched-path audit entries in the transactions that make the changes, and deliver them after.
- [x] Hold a watched-path replacement's entry until the push counts are added, and sweep entries a request could not deliver.
- [x] Tests for the commit, the delayed delivery, refused changes, held entries, and the carried trace; mutation-check them.
