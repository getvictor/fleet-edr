# Keep monitor-mode matches as readable records

Issue #994, first of two changes. This one records the matches and serves them; the second gives the console a way in from a rule's Observed figure.

## The problem

Monitor mode exists so an operator can watch a rule and decide whether to promote it, and today that decision is made from a number. A match in monitor mode goes to a daily counter and a DEBUG log line that production does not emit. No row exists, so there is nothing to open, no process to pivot to, and no way to tell 26 benign updates from 25 benign ones and an intrusion. Reconstructing a hit by hand from Search is not possible at all for a correlation rule.

## What changes

A monitor-mode finding is persisted through the alert path, with everything an alert carries: process link, triggering events and their evidence copies, techniques, severity, and description. It carries a new **disposition** of `monitor`, distinct from an alert's `alert`. Disposition is its own column because both existing candidates already mean something else: `status` is a triage state and a monitor record has not been triaged, and `source` says which subsystem raised the row.

A monitor record is not an alert, and everything that makes something an alert stays with alerts:

- `GET /api/alerts` returns alerts only, unless the caller asks for `disposition=monitor`. No existing client changes behaviour. The list also gains a `rule_id` filter, which is what the console's way in from a rule needs.
- No webhook delivery, no `edr.alerts.created` count, no "detection alert created" log line.
- A status change is refused. A monitor record has not been triaged, and a status write would restart its retention clock.

**Records are deduplicated like alerts**, which is the issue's recommendation: the list reads as distinct findings rather than being padded by batch retries. The daily counter still counts raw matches, so the two numbers can differ, and the second change labels them where they are shown.

**Disposition joins the dedup key.** Left out, a rule promoted to alert would have its first finding dedup into the monitor record already stored for that subject, and raise nothing. With it, promotion leaves stored records as they are and the next finding raises an alert.

**Monitor records expire on their own window**, `EDR_MONITOR_RETENTION_DAYS`, default 7, which is the window the Observed column and the promote decision work over. Independent of the alert and derived-record windows, `0` disables it, and it is capped like them. The alert prune no longer touches monitor records, and the monitor prune never touches alerts. The dogfood host produced 2,327 monitor matches in 7 days against 384 alerts, so inheriting the alert window would have made the table mostly monitor records.

## Rolling upgrade

The migration adds the column with a default of `alert` and swaps the dedup key for one that includes it, in one statement, so there is no moment without a uniqueness guarantee. An older replica keeps writing alerts that land in the new key unchanged. It does not filter reads by disposition, so until it is replaced an older replica lists monitor records the newer replicas wrote, and accepts a status change on one, which sends that record a status-change webhook. This is bounded to the rolling upgrade and documented for operators. Closing it would take either a release split (the column and its readers in one release, monitor writes in the next) or a gate that knows every replica has upgraded, which the server does not have.

## Out of scope

The console surface (the second change), and any outbound notification for monitor records.
