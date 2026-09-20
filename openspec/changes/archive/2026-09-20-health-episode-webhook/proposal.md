# Deliver a host health episode to webhook destinations

Issue #778, second of three changes. It closes the notification gap the first change opened.

## The gap

The first change moved `sensor_recovery_failed` out of the alert queue and into a host health episode. That was the right place for it, and it had a cost the change named: the outbound webhook is alert-shaped, so a host that stopped capturing stopped reaching any destination an operator had configured. The condition was visible in the console and silent everywhere else, and a host that is not capturing is urgent whether or not anyone is looking at the console.

## Why this is not a one-line subscription

The delivery outbox is structurally bound to an alert. Every `webhook_delivery` row carries a non-null `alert_id` with a foreign key to `alerts`, that id is part of the key that makes delivery idempotent, and the event types a destination can subscribe to are a closed `SET`. A health episode has no alert row, and it lives in a different bounded context, so it cannot be given one without putting the fault back in the table it was just moved out of.

## What changes

A delivery row names exactly one subject: an alert, or a health episode. The alert column becomes nullable, a health-episode column joins it with its own idempotency key, and a check constraint holds that exactly one is set. There is no foreign key on the new column, because episodes are owned by the endpoint context and this schema belongs to detection.

Destinations can subscribe to a new event type, `host.health_episode_opened`, filtered by the same minimum severity as alert events. Its envelope carries a `health_episode` body in place of the `alert` body: the episode's kind, the component and part at fault, the fault's own detail, its severity, and when it began on the host.

Alert deliveries are unchanged on the wire. The alert body is omitted only when there is no alert, so every existing alert envelope serializes byte for byte as it did, which a golden test pins.

## Delivering across two contexts

The episode is written by the endpoint context and the delivery by detection, so the two writes cannot share a transaction. The engine records the episode, then enqueues the delivery, and a failure between the two returns an error that has the event redelivered.

That only converges if the enqueue is retried on the redelivery. The episode write is idempotent on its occurrence, so a redelivered event reports the episode as already recorded; enqueuing only when an episode was freshly opened would therefore lose the notification permanently in exactly the case the retry exists for. The enqueue runs whether the episode was just opened or was already there, and the delivery's own idempotency key collapses the repeat.

## What does not change

- A resolution does not notify. The episode closes in the endpoint context's status check-in, which cannot write to detection's outbox without reversing the dependency between the two contexts. The operator-actionable edge is the fault opening, which is what the alert this replaced delivered too.
- The console surface for episodes is the third change.
