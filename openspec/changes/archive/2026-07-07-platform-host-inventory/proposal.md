## Why

The platform-aware event contract (the preceding change) tags each event with its platform, but the host inventory does not record what platform a host runs. An operator looking at the Hosts page cannot tell a macOS host from a Windows one, and the server has no host-level platform to display or to scope host-level decisions by. This change carries the platform from enrollment into the host inventory and surfaces it in the API and the UI, completing the visible half of Phase 0 of Windows support (ADR-0018).

## What changes

- The agent reports its platform (`runtime.GOOS`) at enrollment, alongside the hostname, OS version, and agent version it already sends.
- The enroll endpoint accepts an optional `platform`, rejects an unrecognized non-empty value with a bad-body error, normalizes an absent value to `darwin`, and persists it on the enrollment record.
- The hosts API (`GET /api/hosts`) carries each host's platform, sourced from the enrollment record and empty for a host that has sent events but never enrolled.
- The Hosts UI adds a platform column, mapping `darwin` to macOS, `windows` to Windows, `linux` to Linux, and an empty value to unknown.

`os_version` keeps its current behavior: the agent still reports `runtime.GOOS` for it, and turning it into a real OS version string is a separate follow-up called out in ADR-0018, not part of this change.

## Capabilities

### Modified capabilities

- `agent-enrollment`: the agent reports its platform at enrollment, and the enroll endpoint validates it (rejecting an unknown value), normalizes an absent value to darwin, and persists it on the enrollment record.
- `server-rest-api`: the host list carries each host's platform, sourced from the enrollment record and empty for an un-enrolled host.
- `web-ui`: the Hosts list shows a per-host platform column.

## Impact

- Code (agent): the enroll payload in `agent/enrollment/enrollment.go` gains a `platform` field set to `runtime.GOOS`.
- Code (server): `platform` on `EnrollRequest` and `Enrollment` in `server/endpoint/api`, plus a mirrored platform validator (arch-go forbids an endpoint import of the visibility context, so the small closed vocabulary is duplicated with the same values); validation in `server/endpoint/internal/enroll/handler.go`; a new endpoint migration `server/endpoint/migrations/00007_enrollments_platform.sql` and the `platform` column threaded through `server/endpoint/internal/mysql/store.go` (Register upsert and the List/Get selects) and the service mapping; `Platform` on `HostSummary` and the `COALESCE(e.platform, '')` decoration in `server/detection/internal/mysql/hosts.go`.
- Code (UI): `ui/src/types.ts` (a `platform` field on `HostSummary`) and `ui/src/components/HostList.tsx` (a Platform column and a `formatPlatform` helper), with test coverage.
- Data: one additive migration adding `enrollments.platform` (`NOT NULL DEFAULT ''`). No backfill: a row enrolled before the migration reads back as the empty default, which the UI renders as unknown. Rollback drops the column.
- Wire: the enroll payload gains an optional `platform` key; a legacy agent that omits it still enrolls (the server defaults it to darwin). The hosts API response gains a `platform` field.
