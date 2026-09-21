# Tasks

- [x] Migration: `webhook_delivery.alert_id` nullable, `health_episode_id` with its own idempotency key, a check that exactly one subject is set, and `host.health_episode_opened` in the destination event-type set
- [x] `OpenHealthEpisode` returns the episode id on both a fresh open and a redelivery, so the enqueue can key on it
- [x] Envelope: the alert body is omitted when there is no alert, a health-episode body is added, and alert envelopes stay byte-identical (golden test)
- [x] Detection store: enqueue a health-episode delivery per matching destination, idempotent per episode and destination
- [x] Engine: enqueue after recording, on a fresh open AND on a redelivery, so a lost enqueue converges
- [x] Destination API and the webhooks settings UI accept the new event type
- [x] Mutation-check the convergence: an enqueue gated on a fresh open must fail a test
- [x] Manual QA: a destination receives a signed delivery for an episode opening, on the dev server
