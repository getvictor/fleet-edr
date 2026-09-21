# Open a rule's monitor records from its Observed count

Issue #994, second of two changes. The first (`monitor-mode-records`) keeps a monitor-mode match as a readable record and serves it through `GET /api/alerts?disposition=monitor`. This one is the console's way in.

## The problem

The records exist, but nothing in the console reaches them. The detection-tuning page's Observed column is where an operator decides whether to promote a rule, and it still offers only a count. A monitor record opened by URL renders on the alert investigation page, and that page offers Acknowledge and Resolve, which the server refuses because a monitor record has no triage.

## What changes

- **A records link beside each Observed count** opens a page listing that rule's monitor records, newest first. Each row links to the record's process tree, the same investigation surface an alert uses.
- **The records page explains the numbers.** Records collapse repeat matches on the same process and are kept on their own retention window, so there can be fewer records than the count. Stated where the two meet, so the difference does not read as lost data. The Observed note says the same.
- **A monitor record's detail shows no triage.** The investigation page shows a "Monitor record" badge where the Acknowledge and Resolve controls would be. Its back link goes to the rule's records rather than to the Alerts queue, which does not list it.

It is its own page rather than the Alerts page with a filter, because everything that page carries around its table (the status filter, triage controls) is wrong for a monitor record.
