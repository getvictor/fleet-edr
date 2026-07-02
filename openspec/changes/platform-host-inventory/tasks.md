# Tasks

## Agent

- [x] Report `platform` (runtime.GOOS) in the enroll payload (`agent/enrollment/enrollment.go`).

## Server

- [x] Add `Platform` to `EnrollRequest` and `Enrollment` in `server/endpoint/api`, plus a mirrored platform validator.
- [x] Validate platform in the enroll handler: reject unknown, normalize absent to darwin.
- [x] Migration `server/endpoint/migrations/00007_enrollments_platform.sql`; thread platform through the Register upsert, the List/Get selects, and the service mapping.
- [x] Add `Platform` to `HostSummary` and `COALESCE(e.platform, '')` to ListHosts.

## UI

- [x] Add `platform` to the `HostSummary` type and a Platform column with a `formatPlatform` helper.

## Tests

- [x] Agent enrollment test asserts the payload carries the platform.
- [x] Enroll handler tests for normalize-to-darwin and reject-unknown.
- [x] ListHosts integration test carries the enrollment platform.
- [x] HostList component test renders the platform column; `formatPlatform` unit test.
