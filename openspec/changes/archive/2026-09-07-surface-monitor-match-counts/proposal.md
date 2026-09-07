# Surface the recorded monitor-match counts to the operator

## Why

Issue #813, third of three. #816 records what every monitor-mode rule has been matching, per rule and host and day. Nothing reads it. An operator deciding whether to promote a rule still has the same problem the issue opened with: the evidence exists and is not where the decision is made.

## What changes

`GET /api/v1/detection-config/rule-match-counts` returns, per rule that matched, the total over a window, how many distinct hosts contributed, and when it last matched. The detection-tuning table shows those beside the mode control, so "this matched 4,000 times across 3 hosts last week" sits next to the switch that would turn it into alerts.

Three numbers rather than one because equal totals mean opposite things. Ninety matches on one host is a candidate for an exclusion; ninety spread over thirty hosts means the rule is too broad and should stay in monitor. A single figure cannot separate them, and separating them is the whole reason the recorder keeps a host dimension.

The window defaults to a week, is capped at the retention window, and is echoed in the response, because a caller that asked for ninety days and received thirty must not describe the number as covering ninety.

## Impact

One new read endpoint on an existing surface, gated by the read action already used there, and a column in the detection-tuning table. No new storage: this reads what #816 already writes.

The number is labelled as an approximation everywhere it is shown. It counts matches, and alerts deduplicate on (host, rule, subject) permanently, so a rule that keeps matching one subject would raise one alert rather than the many this reports. Presenting it as "alerts you would have received" would be a forecast the data does not support.
