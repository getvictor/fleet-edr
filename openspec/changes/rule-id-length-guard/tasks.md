# Tasks

- [x] Add `api.MaxRuleIDLen` as the single permitted length, with the reasoning for the value.
- [x] Widen `alerts.rule_id` (detection migration 00013), explicitly INPLACE / LOCK=NONE, verified against the pinned MySQL 8.4.9.
- [x] Widen the three rules-context columns (rules migration 00006), carrying `detection_exclusions.rule_id`'s `DEFAULT ''` forward.
- [x] Share one length refusal across all three loaders, including the imported path the defect came from.
- [x] Catalog-wide test measuring every shipped rule, plus a test pinning WHY the columns are wider than 64.
- [x] Loader-level test for the imported path, driven through an in-memory FS because a filesystem cannot hold the filename.
- [x] Integration test reproducing the outage: promote the 70-character rule, assert the alert persists AND the queue is acknowledged.
- [x] Mutation-test each guard (four caught; one inert version rewritten until it bit).
- [x] Live QA: both migrations applied to a dev database holding 61 alert rows, and the promoted rule alerted end to end.
- [x] File the unbounded-nack-loop defect separately (#836).
