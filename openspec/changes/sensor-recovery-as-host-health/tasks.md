# Tasks

## This change (recording)

- [x] Migration: `host_health_episodes`, unique on the occurrence (host, source event) so a redelivered report collapses onto the record it already made, open or closed, enforced by the schema rather than by a read-then-write
- [x] `endpoint/api`: the episode type and the recorder interface the detection engine depends on
- [x] `endpoint` store: open an episode, close it on recovery, and leave a redelivered occurrence alone
- [x] Close open episodes from the status check-in when the component reports healthy
- [x] `rules/api`: carry the provider, outcome, and attempt count on the finding as fields
- [x] Engine: route a health-kind finding to the recorder instead of to the alerts table, leaving projections and detections alone
- [x] Mutation-check the routing: a health finding that still reaches the alerts table must fail a test
- [x] Confirm no alert row is created for the rule end to end, on the dev server

## Deferred to the operator-surface change

- [ ] `GET` surface for episodes, authz-gated
- [ ] UI: the host health surface that reads them
- [ ] Webhook: a health event, closing the notification gap this change opens
