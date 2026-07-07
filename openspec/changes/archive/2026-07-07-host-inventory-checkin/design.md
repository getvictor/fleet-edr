## Context

PR #572 built the status check-in: `agent/health` registry + poster (startup, debounced transitions, 60s floor), `POST /api/status` host-token-authed handler, `RecordStatus` service, `host_health` current-state table. `StatusReport` is explicitly additive: open vocabularies, custom JSON columns, idempotent full-replace, last-writer-wins by `reported_at_ns`. Meanwhile identity fields (`hostname`, `agent_version`, `os_version`) live on `enrollments` and refresh only inside `Store.Register`'s `ON DUPLICATE KEY UPDATE`, which a healthy agent never re-triggers. The former #437 specified a periodic "host inventory" document; #572 built the channel it should ride.

## Goals / Non-goals

**Goals:**

- Identity fields on the host record track reality within one check-in interval (60s), with no new endpoint, auth path, or scheduler.
- Additive wire change: old agents and old servers interoperate in both directions.
- Friendly OS values (`macOS 26.4` not `darwin`) from both enrollment and check-in.

**Non-goals:**

- No UI in this PR (PR 2 of #579 renders the header).
- No hardware inventory (model, serial), disk encryption, or logged-in user; the struct is additive so those append later without a wire break.
- No change to health semantics, rollup, or the `host_health` table.

## Decisions

- **Ride `POST /api/status`, not a new endpoint.** The poster already posts on exactly the triggers #437 wanted (startup, on-change, periodic), with token auth and re-enroll-on-401. A second check-in endpoint would duplicate all of it. The `inventory` field is optional; `RecordStatus` treats absence as "no inventory claim" and touches nothing.
- **Persist into `enrollments`, not `host_health`.** Enrollment is the identity row every reader already joins (`ListHosts`, PR 2's detail endpoint). Widening it with `os_name`/`os_build` keeps one source of truth for identity; `host_health` stays purely health. The row's meaning shifts from "identity at enroll time" to "latest known identity", which is what every consumer actually wants; `enrolled_at` still records enrollment time.
- **Unconditional UPDATE, no change detection.** The poster posts at most ~1/min/host; MySQL skips the physical write when values are identical, so a diff guard on either side is complexity without a measurable win. No per-replica state (ADR-0010 clean).
- **Inventory collection is pure Go, no exec.** Hostname from `os.Hostname()`; `ProductName`/`ProductVersion`/`ProductBuildVersion` parsed from `/System/Library/CoreServices/SystemVersion.plist` (howett.net/plist is already an agent dependency); agent version from the existing build-time version var. Missing plist (dev container, tests) degrades to empty OS fields, which the server stores as claimed.
- **Enrollment sends the same fields.** `Register` already refreshes on re-enroll; sending friendly values there too fixes the `darwin` placeholder for fresh enrolls without waiting for the first check-in.

## Risks / Trade-offs

- [A malicious or buggy agent can rewrite its own hostname/OS row every minute] → identical trust model to enrollment today; the field is self-reported inventory either way, and the host token scopes writes to the host's own row.
- [Enrollments row now updated outside the enroll path] → the write is in the endpoint context's own store, same table owner; `enrolled_at` is not touched.
- [`updated` semantics for PR 2's "identity as of" display] → add `inventory_reported_at_ns` alongside the columns so the reader can show staleness honestly.
