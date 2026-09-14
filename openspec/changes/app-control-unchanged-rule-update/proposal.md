# An application-control rule update that changes nothing succeeds

## Why

Issue #1052. `PATCH /api/v1/app-control/rules/{id}` returned 404 `application_control.rule_not_found` when the request set fields to the values the rule already had. The store treated a zero affected-row count as a rule deleted between its lookup and its update, but the MySQL driver reports changed rows, so an update that changes nothing also reports zero. A retried request, or an operator saving a rule without editing it, got "not found" for a rule that exists. It affected every field, and Detect mode made it easier to reach, since the console's enforcement switch sends only `enforcement`.

## What changes

- **An update that changes nothing succeeds** with 200 and the rule as it is.
- **It is not a mutation.** The policy version does not advance, no `set_application_control` command is enqueued, and no audit event is recorded, because nothing changed: hosts already hold the rule, and there is no change to attribute.
- **Whether anything changes is decided by comparing the request with the rule.** The update reads the rule under a row lock and compares each supplied field with its current value, rather than reading the `UPDATE`'s affected-row count, which reports changed or matched rows depending on the DSN's `clientFoundRows`. A rule deleted concurrently still reads as not found. The update already took that row lock; taking it at the lookup adds no lock and keeps the rule-then-policy order single-rule mutations have always used.
- **The audit requirement names the exception.** "Rule lifecycle audit events" is restated so a rule update that changes nothing is not one of the updates it requires an event for.

## Out of scope

- The lock order itself. Single-rule create, update and delete take the rule row before the policy row, while bulk upsert locks the policy first, so a single-rule change and a bulk upsert touching the same rule can deadlock and one of them fails. That predates this change and is tracked in #1057.
