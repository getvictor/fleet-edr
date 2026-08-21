# Bound the candidate-host hint's scan

## Why

The processor asks the queue "which hosts have claimable work, oldest first" on every cycle. That hint's predicate ORs across the two claim states, never-claimed and claim-expired, and no index is ordered by timestamp across states, so it degraded into a full scan plus a temp-table aggregate. Its cost grew with backlog depth, which means it was slowest exactly when the pipeline was furthest behind and could least afford it. At the 500ms poll interval with four workers that is roughly eight full scans a second against the queue (issue #720).

Measured on MySQL 8.4 over a seeded 200k-row queue across 200 hosts, 2k rows in flight and 2k held by expired claims: **67.6ms before, 3.3ms after**, returning an identical host list.

## What changes

The hint splits into one arm per claim state, each an index range read in timestamp order, backed by a new `(processed, timestamp_ns, claimed_at_ns, host_id)` index that is covering for all three reads it makes. One index rather than two, because `event_queue` is the ingest hot path and every index is maintained on insert; the single combined index also measured faster than the two-index alternative (3.3ms against 5.3ms).

Each arm reads only a bounded window of its oldest rows, and **that is the observable behavior change this proposal exists to state.** The hint becomes approximate: a host whose oldest claimable event falls outside the window is not offered that cycle.

## Why the approximation is safe, and why it is not the failure it resembles

A hint that omits an eligible host looks a lot like the starvation bug fixed in #719, so the distinction is worth stating rather than assuming.

The window is ordered by timestamp, so the globally oldest claimable event is always inside it. A host is skipped only when the window is full of events strictly older than anything that host has, and draining those first is the correct priority. Progress is therefore never blocked, only ordered, and the deferral is bounded by the older work draining.

The dangerous direction is the opposite one and is unchanged: offering a host that is BLOCKED behind an unexpired in-flight event costs the whole fleet a claim lease, because such hosts sort to the front of the candidate window and hold it. The in-flight floor join that prevents that is preserved exactly.

Missing an eligible host costs one idle worker for one 500ms cycle. Offering a blocked one costs the fleet five minutes.

## Why a new requirement rather than modifying the existing one

The natural home is `The processor scales across replicas via SKIP LOCKED`, which already owns the claim and the blocked-host scenario. It already carries an in-flight MODIFIED delta from `per-host-claim-affinity`, and two in-flight deltas against the same requirement is a known archive hazard in this repo: the second to archive silently drops the first's scenarios. Stating the hint's cost contract as its own requirement avoids the collision and is separable on its merits, since it governs what the hint may leave out rather than how the claim behaves.
