# Refine the hosts page with a fleet summary and enrollment-backed host columns

## Why

The hosts page is the operator's landing view, but it keys every row on the raw hardware UUID and shows no fleet-level overview. Operators recognize machines by hostname, not UUID, and have no at-a-glance read on how much of the fleet is online. The enrollment hostname and OS version are already collected and stored at enrollment (`enrollments.hostname`, `enrollments.os_version`); they are simply not surfaced on the hosts list, which selects only `host_id`, `event_count`, and `last_seen_ns`.

## What changes

- **`GET /api/hosts` carries the enrollment hostname and OS version.** `detection.api.HostSummary` gains `hostname` and `os_version`, and `detection`'s `ListHosts` query LEFT JOINs the endpoint context's `enrollments` table on the shared `host_id`. LEFT (not INNER) so a host that has sent events but never enrolled still appears, with empty hostname/OS version; `COALESCE` folds the outer-join NULLs into empty strings.
- **The hosts page opens with a fleet-overview summary strip.** Three stat cards (Online / Offline / Total hosts) computed from the existing `isOnline(last_seen_ns)` classification, rendered above the table. The page header is dropped so the page opens directly into the summary.
- **The host table is enriched.** The `Host ID` column becomes a `Host` column showing the enrollment hostname over the full hardware UUID (UUID alone when no hostname is known); a new `Platform` column shows the OS version; the `Events` column is right-aligned with tabular figures. Status, last-seen, and row-click-to-process-tree are unchanged.
- **A shared `StatCard` / `SummaryStrip` UI primitive is extracted.** The summary strip reuses one component rather than bespoke markup; the existing inline stat cards on the ATT&CK coverage page are refactored onto the same primitive, removing the duplicated `.attack-coverage__summary` / `__metric` styling.

### Not in this change

- No change to enrollment collection or the `enrollments` schema; hostname and OS version are already stored.
- No new hosts-page filtering, search, or sorting; the row set and ordering (`last_seen_ns DESC`) are unchanged.
- `host_id` remains the stable key and routing param; hostname is display-only.
