## 1. Wire + server

- [x] 1.1 Add `Inventory` struct (`hostname`, `os_name`, `os_version`, `os_build`; agent version rides the report's top-level field) as an optional pointer field on `StatusReport` in `server/endpoint/api/status.go`; PBT round-trip test (`Marshal ∘ Unmarshal == identity`)
- [x] 1.2 Migration `server/endpoint/migrations/00006_*.sql`: add `os_name`, `os_build` (VARCHAR, default '') and `inventory_reported_at_ns` (BIGINT, default 0) to `enrollments`
- [x] 1.3 Store method `UpsertInventory(hostID, inv, reportedAtNs)` updating the enrollment row (no-op when no row exists yet is acceptable: a host always enrolls before it can check in)
- [x] 1.4 `RecordStatus`: after snapshot validation succeeds, persist inventory when present; absent inventory touches nothing; a rejected snapshot writes nothing (spec markers `server-persists-inventory-from-the-status-check-in/*`)

## 2. Agent

- [x] 2.1 Inventory collector (hostname via `os.Hostname`, OS fields parsed from `/System/Library/CoreServices/SystemVersion.plist`, graceful empty on missing source) with unit tests against a fixture plist (spec markers `status-report-carries-host-inventory/*`)
- [x] 2.2 Include inventory in the poster's payload, re-collected per post (a hostname syscall plus one small file read) so a hostname rename or OS change reaches the server within one interval without an agent restart
- [x] 2.3 Enrollment request sends the friendly OS product version instead of `runtime.GOOS` (spec marker `enrollment-reports-friendly-os-identity/*`)

## 3. Verification

- [x] 3.1 `go test ./server/... ./agent/...`, `go vet -tags integration ./...`, `task lint:go`, `tools/spectrace check --strict`, `openspec validate --all --strict`
- [x] 3.2 Manual QA on dev server: run the agent (or curl a forged status post with inventory) against `task dev:server`, confirm the enrollments row updates in MySQL and an inventory-less post leaves it unchanged

## 4. Docs

- [x] 4.1 CHANGELOG entry under 0.4.0 (user-facing: host identity stays current without re-enroll)
