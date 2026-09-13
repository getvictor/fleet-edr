# Tasks

- [x] `EDR_ALERT_RETENTION_DAYS`, default 180, independent of `EDR_RETENTION_DAYS`, 0 disables
- [x] Alert prune on the existing retention pass, before the process prune, measured from last triage activity
- [x] Delete each batch's event links and alerts in one transaction, since `alert_events` does not cascade
- [x] The runner's loop runs when either window is enabled, not only the process one
- [x] Index on `alerts(updated_at)`
- [x] Alert rows-deleted metric of its own
- [x] Document the default as a stated retention policy
- [x] Mutation-check the foreign-key handling, the loop, the age basis, and the prune order
- [x] Manual QA on the dev server
