## Context

`GET /api/hosts` (detection context) already joins the endpoint context's `enrollments` and `host_health` tables per host; `GET /api/hosts/{host_id}/health` serves one host's health via the `HostHealthReader` seam. PR 1 of #579 added `os_name`, `os_build`, and `inventory_reported_at_ns` to `enrollments` and keeps identity fresh via the status check-in. The host page renders the raw host id as a title link (`ui/src/components/ProcessTree.tsx:532`) with `HostHealthPanel` below.

## Goals / Non-goals

**Goals:**

- One request returns everything the header needs; the header cannot block the investigation surface.
- Mirror the established seams: the endpoint sits beside the health route, gated on the same host-read action, with the same cross-context read posture.

**Non-goals:**

- No fleet search, pivots, or response actions (later epic stories).
- No changes to the health panel or the hosts list.

## Decisions

- **Detection context serves the endpoint.** It owns the `hosts` liveness row and already reads `enrollments`/`host_health` cross-context for the list; a new `HostDetailReader` seam + `host_detail_handler.go` file mirrors `host_health_handler.go` exactly (route + gate + handler co-located, 503 when unwired).
- **`FROM hosts` base, LEFT JOIN identity**, matching `ListHosts`: an unknown host id 404s, a never-enrolled host that has sent events returns empty identity strings. The reachable UI paths (host list, alert pivot) only produce host ids with a `hosts` row.
- **Single fetch, best-effort render.** The header fetches once per hostId; on failure the title falls back to the raw host id and the meta row is omitted (the same degrade posture as `HostHealthPanel`). The tree never waits on it.
- **Online/offline derives client-side** from `last_seen_ns` with the host list's existing 5-minute predicate, reusing its formatting helpers (`ui/src/time.ts`) rather than duplicating a server flag.

## Risks / Trade-offs

- [Header + health panel are two requests on page load] → both are single-row reads; merging them into one endpoint would couple the health panel's refresh cadence to identity. Acceptable now; PR for a combined view can come with the timeline work if request count ever matters.
- [`enrolled_at` string formatting across locales] → render with the same date formatting the alert list already uses.
