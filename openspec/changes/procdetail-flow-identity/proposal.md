# Attribute process-detail flows by generation identity

## Why

The process-detail panel shows "No network activity" for a process whose outbound connection is the very thing an alert fired on (issue #716, dogfood alert 785). Detection and the panel correlate a flow to a process by two different methods, and only detection's is sound.

Detection resolves a flow by `(host, pid, pidversion)` identity, so alert 785 attributed correctly. The panel instead built an ingest-time window from the process lifetime, `[fork_ingested - 1s, exit_ingested + 1s]`, and asked for every flow on that pid inside it. The flow and the process's exit travel up the agent uploader in SEPARATE batches, so a short-lived process's flow routinely ingests after its exit: measured 3.5s past the flow's own stamp, which is 2.0s past the window's upper bound. The flow was filtered out.

The same pid-keyed filter also mis-attributes. A sibling generation of that pid that had not exited carried an open-ended window, so the flow appeared under the generation that did NOT own it while being invisible under the one that did.

## What changes

- The detail read is scoped to one generation. A flow carrying a `pidversion` is attributed by identity alone, with no lifetime window, which is what makes it robust to ingest lag. A flow carrying none keeps the window, because identity cannot speak for it.
- The window's upper bound for an exited process widens from 1s to 60s. It was sized for reordering within one upload; the real gap is between two uploads. This now applies only to flows that carry no `pidversion`.
- The predicate is shared with the alert-chain timeline scope, which already matched on `(pid, pidversion)`, so the two reads cannot drift on the matching rule.

Attribution alone does not clear the reported symptom, because the panel could not open the generation that owns the flow. A re-exec preserves the chain's original fork time, so every generation of one chain shares it and `GetProcessByPID`'s `(fork_time_ns DESC, id DESC)` ordering resolves the newest whatever as-of instant it is given. Verified against the running dev server: asking for the bash generation's own exec instant returned the curl generation, which then correctly reported no flows, so the panel still read "No network activity" for the connection under investigation.

- The detail endpoint accepts an optional `pidversion` naming one generation, resolved by identity. Absent, the as-of read is unchanged, which is what the tree and timeline rely on. A malformed value is a 400 and an unknown one a 404, so a bad value cannot quietly return a different generation than the caller asked for.
- The panel passes the pidversion of the node it is showing, so clicking a process opens that process.

## Non-goals

- The orphan fork row visible in the issue's data is issue #714 and is untouched here.
- The ESF handler-time stamping that makes detection's network arm MISS is issue #710. Here the alert fired correctly and only the display was wrong.
- No migration. The fix is a read-path change, so existing flows attribute correctly on the next request.
