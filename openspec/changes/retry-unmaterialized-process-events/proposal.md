# Retry rule evaluation when an event's subject process is not yet materialized

## Why

Since intra-replica processor concurrency (#535, PR #541), two claim batches of the same host can be in flight at once, and the same window has always existed across replicas (ADR-0011). Rule evaluation runs after its OWN batch's process rows are flushed, but nothing orders it after a CONCURRENT batch's flush. When the claim boundary splits an attack's `exec` from its follow-on event (the `open`, the block, the exec's own evaluation), the rule's `GetProcessByPID` misses, every affected catalog rule treated that miss as "no finding", and the event was acked, so the alert was silently and permanently lost. The 2026-07-02 nightly demo run lost exactly the `sudoers_tamper` alert this way (run 28580179395: the source-leg smoke test failed with five of six expected rules fired and no error logged; the identical commit passed on re-run, confirming a probabilistic race, not a regression).

## What Changes

- **A missing subject process becomes a retryable condition instead of a silent drop, bounded by a grace window.** Rules that resolve the process an event is about (the pid in the event's own payload, whose fork/exec is ordered earlier in the same host stream) now raise a typed sentinel (`rules/api.ErrProcessNotYetMaterialized`) when the lookup misses and the event's ingest age is inside a fixed materialization grace window (30s). The engine propagates exactly that error class (ordinary rule failures keep the log-and-swallow per-rule isolation), so the processor nacks the batch and re-evaluates it on a later cycle, by which time the concurrent flush has committed. Alert dedup makes the re-run idempotent. Past the grace window the historical silent skip applies, so an event whose process genuinely never materializes (a pre-capture pid, an agent that dropped the fork/exec) cannot hold its batch in a retry loop.
- **Scope: subject-process lookups only.** The nine wired call sites are sudoers_tamper, credential_keychain_dump, application_control_block, persistence_launchagent, dyld_insert, shell_from_office (its own pid), osascript_network_exec and suspicious_exec (their temp-exec pid). Ancestor and parent-chain walks keep the silent skip: a parent can legitimately predate the capture. dns_c2_beacon's flow resolution also keeps the silent skip, deliberately: it resolves before its suspicion gate (the gate reads the process path), so a retryable miss there would fire for every outbound connect whose exec the agent dropped under load, turning sustained load into batch-retry storms. All wired call sites resolve only after a payload-level pre-filter, so the sentinel is raised only by already-rare events.
- **The demo seeder verifies one fired alert per expected rule.** `verify` previously passed on "any detection alert", which let the seeder exit 0 with one rule's alert missing and deferred the failure to the Playwright smoke. It now polls until every woven attack's `ExpectRule` has a fired alert, and its timeout error names the missing rules.
- **Unchanged:** the claim/ack/nack queue contract, the batch flush, the alert schema and dedup, rule match logic, and every wire shape. No new configuration surface: the grace window is a compiled constant.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `server-detection-rules-engine`: a new requirement that a young event whose subject process row is missing fails the batch with a retryable error class (so the processor re-evaluates it) while an event past the grace window keeps the historical skip.

## Impact

- **Affected specs:** `server-detection-rules-engine` (1 added requirement).
- **Affected code:** `server/rules/api/types.go` (sentinel), `server/rules/internal/catalog/materialize.go` (grace helper) plus the eight wired rules, `server/detection/internal/engine/engine.go` (propagate the sentinel), `server/cmd/fleet-edr-demo-seed/seed.go` (per-rule verify).
- **Performance:** the check is one integer comparison on an already-rare nil-lookup branch; a batch retry occurs only when the race actually fires and resolves on the next poll tick. The grace window also self-disables under backlog (events arrive at evaluation already older than the grace), so a stressed processor keeps pre-change behaviour rather than amplifying the backlog with retries.
- **Residual risk (documented):** dns_c2_beacon can still lose an alert to the materialization race; accepted to avoid flow-volume retry storms. The tightened seeder verify converts that loss from a silent partial seed into a loud, named failure.
