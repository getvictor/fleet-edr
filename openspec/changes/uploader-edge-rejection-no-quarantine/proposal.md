# Keep good telemetry queued when the ingest endpoint blanket-rejects uploads

## Why

The agent uploader treats a sustained HTTP 403 on `POST /api/events` like a malformed-payload 4xx: after `ClientErrorQuarantineThreshold` consecutive failed drain ticks (default 10) it seals the batch (`uploaded=1`), stops dequeuing it (#253 quarantine), and silently drops good telemetry. But the EDR ingest route never itself returns 403. The host-token middleware (`server/endpoint/internal/middleware/hosttoken.go`) returns only 401 / 503, and the intake handler (`server/detection/internal/intake/handler.go`) returns only 200 / 400 / 413. A 403 the agent sees is therefore always injected by an edge/proxy/WAF or a wrong/unhealthy origin: the batch content is fine, the endpoint is rejecting everything. The same holds for every 4xx other than 400 (poison content), 401 (re-enroll), and 413 (too large): 404, 405, 408, 429, 451, and the rest are all infrastructure signals on this route, not per-batch content verdicts.

This was a real incident (2026-06-16): a fresh Render deploy returned 403 at the edge while the origin was unhealthy; every batch burned its 10-tick budget and was dropped while the endpoint was unreachable (#398). A "back off and keep the queue" recovery would have preserved that telemetry.

## What changes

- **The quarantine budget is reserved for HTTP 400 only.** 400 is the single status the ingest contract emits to mean "this batch's content is bad" (`invalid_json` / `host_id_mismatch` / `missing_fields_at_<i>`). A persistent 400 still seals the batch after the threshold, exactly as today.
- **Every other non-2xx the route never legitimately emits as a content verdict (any 4xx except 400/401/413) is treated as a transient endpoint rejection.** The batch is kept queued (`uploaded=0`), the uploader backs off to the next drain cycle, and uploads resume automatically when the endpoint returns 2xx. Retention during the rejection window is bounded only by the existing `EDR_AGENT_QUEUE_MAX_BYTES` lossy cap, not by the quarantine budget.
- **A distinct, loud signal marks the "endpoint rejecting uploads" state.** A dedicated WARN (`audit=uploader.endpoint_rejecting`, with `status_code`) and an OTel counter (`edr.agent.uploader.endpoint_rejected`, by `status_code`) fire so an operator sees "server unreachable / misconfigured" rather than a quiet drop.
- 401 (re-enroll) and 413 (split-and-retry) keep their existing handling unchanged.

Affected code: `agent/uploader/uploader.go` (status classification + recovery routing) and `agent/metrics/metrics.go` plus the uploader's `MetricsRecorder` interface (the new counter). Agent-side persistence/recovery only: no wire-format, schema, server, or migration change.

### Not in this change

- No change to the 400 quarantine path, the 401 re-enroll path, or the 413 split-and-retry path.
- No change to the queue's lossy `EDR_AGENT_QUEUE_MAX_BYTES` cap: a long outage still bounds agent memory by dropping the oldest rows at the cap (lossy, counted in `edr.agent.queue.dropped`), which is a separate, already-signalled mechanism from quarantine.
