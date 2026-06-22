# Exec-auth result caching and gzip telemetry upload

## Why

Two independent efficiency wins that share a single macOS VM QA session, shipped together:

- **#209**: the AUTH_EXEC handler answers every ALLOW with `cache: false`, so a fork-exec storm of an already-allowed binary (a compiler, linker, or interpreter re-execed in a tight loop) re-enters the handler every time: lock acquisition, snapshot read, and an optional hash lookup the kernel cache exists to elide. Santa caches ALLOW for stable identities. We do not.
- **#405 (compression slice)**: the agent posts raw, uncompressed JSON batches to `POST /api/events`. Event payloads are highly compressible (~1.3 KB JSON each, repetitive keys), so gzip cuts upload bandwidth several-fold on the insert-heavy ingest path at pilot and fleet scale. This is the compression slice only; persistent-connection and transport modernization stay in #405.

## What changes

### #209 Kernel-cached ALLOW with snapshot-driven invalidation

- A fully decided ALLOW (`AuthDecision.allow`) and the self-allow failsafe respond with `cache: true`; the result is a function of the binary's stable identity tuple and the active snapshot.
- Undecided ALLOWs (cold cache / deadline / read failure) and every DENY stay `cache: false`.
- The load-bearing piece: `ApplicationControlStore` flushes the kernel AUTH cache (`es_clear_cache`) on every accepted snapshot swap, so a cached ALLOW cannot outlive a rule change. Fired on acceptance (version advance, epoch re-sync, or policy retarget), not only on a version bump, because all three mutate the active ruleset.

### #405 gzip request compression for `POST /api/events`

- Agent gzips the request body and sets `Content-Encoding: gzip`. The raw JSON still flows through the 413 split-and-retry path (which splits by event count), so that recovery is unaffected.
- Server decompresses when `Content-Encoding: gzip` is present and caps the DECOMPRESSED stream at the existing per-request byte cap, so a gzip bomb cannot expand past the limit. A corrupt gzip stream is rejected distinctly from an oversize body. The uncompressed path stays supported (the demo-seed tool and any non-gzip caller keep working); no agent/server version lockstep is required.

## Impact

- Affected specs: `extension-application-control` (ADDED requirement), `agent-event-uploader` (MODIFIED), `server-event-ingestion` (MODIFIED).
- Affected code: `extension/edr/extension/{ESFSubscriber,ApplicationControlStore,AuthExecDecider}.swift`; `agent/uploader/uploader.go`; `server/detection/internal/intake/handler.go`.
- No wire-struct or event-field change; no new struct, so no PBT round-trip obligation. Behavior verified by unit tests plus a macOS VM QA run (ESF cache behavior must be exercised live before RC).
