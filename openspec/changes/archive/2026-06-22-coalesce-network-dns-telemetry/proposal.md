# Coalesce network and DNS telemetry before enqueue

## Why

`network_connect` + `dns_query` are ~34% of `events`-table rows on the Render pilot (issue #408), and much of it is repetitive: the same process reconnecting to the same destination 5-tuple, and the same domain resolved over and over. The extension correctly emits one event per flow / per query (observation-only capture is a hard requirement), but uploading every occurrence verbatim is wasteful when a representative event plus an occurrence count carries the same detection-relevant signal.

## What changes

- **The agent coalesces repetitive `network_connect` and `dns_query` events in a bounded time window before enqueue.** A new pre-enqueue stage sits between the XPC receiver and the SQLite queue. Within each window it collapses events that share an identity key into one representative event:
  - `network_connect` key: `(pid, pidversion, protocol, direction, remote_address, remote_port)`.
  - `dns_query` key: `(pid, pidversion, query_name, query_type)`. This also merges a query event with its follow-on response event (same key), so a resolved lookup collapses to one event carrying the answer.
- **The representative preserves detection fidelity:**
  - The envelope `timestamp_ns` is the **earliest** occurrence, so the DNS-to-connect correlation window (the `dns_c2_beacon` 30s window, `suspicious_exec`) is never shortened.
  - The payload gains `coalesced_count` (occurrences represented) and `last_timestamp_ns` (the latest occurrence's time), so the time span and frequency are retained.
  - For `dns_query` the representative's `response_addresses` is the **union** of all addresses seen across the merged queries, so a later connection to any resolved IP still correlates.
- **Everything else passes through immediately.** Only `network_connect` and `dns_query` are buffered. `exec`/`fork`/`exit`/`snapshot_heartbeat`/application-control events are enqueued with no added latency.
- **Bounded latency and lossless shutdown.** A representative is held at most one window. The buffer is flushed on agent shutdown so no buffered telemetry is lost on a clean stop.
- **New config:** `EDR_NETWORK_COALESCE_WINDOW` (default `10s`; `0` disables coalescing and restores per-occurrence upload). The default is deliberately well under the 30s beacon-correlation window so coalescing can never push a representative outside it.

## Detection-fidelity argument

`dns_c2_beacon` fires on a `network_connect` whose remote was resolved by a suspicious-path process via a `dns_query` in the prior 30s, escalating on high-entropy / DGA domains. It correlates a single connect to a prior query; it does not count connection frequency. Coalescing connects to one representative (earliest timestamp, union of DNS answers preserved) keeps that correlation intact. `suspicious_exec`'s network fallback walks the process tree from the connecting PID and is likewise unaffected by occurrence count. The efficacy corpus is re-run to confirm.

### Not in this change

- Heartbeat drop and the events index/PK diet (separate changes).
- Upload bandwidth optimization (gzip/zstd/HTTP-2), tracked in #405.
- Server-side aggregation or any change to how the server stores or reads these events (the new payload fields are optional and ignored by existing rules).
