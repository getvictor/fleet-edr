## Why

On prod, the server exported about 520,000 spans an hour with one enrolled host, and a 24-hour trace query exceeded the trace store's memory limit. Almost every span was a root span from background work: about 100,000 `detection.rule.evaluate` spans and about 400,000 database client spans an hour. No HTTP request started that work, so the route-tier sampler saw only unclassified span names and kept them all at 100%. The orphaned spans were also useless for diagnosis: a rule evaluation was not connected to the batch it ran on, and a query was not connected to the work that issued it.

The periodic sweeps had the opposite problem. They set span attributes such as the retention cutoff on a context that held no span, so those attributes were never exported.

## What changes

- The detection processor opens one root span per host batch it claims. The sampling policy classifies that span high-volume, with the agent ingest traffic that drives it. The per-rule evaluation spans and the batch's queries are its children, so one decision covers the whole batch.
- Each periodic sweep pass (retention, process TTL, queue prune, webhook delivery) runs under its own root span at full fidelity, and its attributes land on it.
- A database query made with no active span records no span. The connection housekeeping spans (session reset, statement prepare, row iteration) are no longer emitted. Database latency metrics still record every query.

## Not changed

The sampling ratios, their settings API and defaults, the HTTP route tiers, and every metric are unchanged.
