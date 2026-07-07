## 1. Server

- [x] 1.1 `api.HostDetail` type in `server/detection/api/types.go` (identity + liveness + rollup fields)
- [x] 1.2 Store method `HostDetail(ctx, hostID)` in `server/detection/internal/mysql/hosts.go`: `FROM hosts` LEFT JOIN `enrollments` + `host_health`, COALESCE defaults, `sql.ErrNoRows` for an unknown id
- [x] 1.3 `host_detail_handler.go` mirroring the host-health seam: `HostDetailReader` interface, `SetHostDetail`, route `GET /api/hosts/{host_id}` gated on host read, 404 on no rows, 503 unwired; bootstrap wiring
- [x] 1.4 Handler + store tests with spec markers (`host-detail-endpoint/*`), including the 404 and never-enrolled cases

## 2. UI

- [x] 2.1 `HostDetail` type in `ui/src/types.ts`; `getHostDetail` in `ui/src/api.ts`
- [x] 2.2 `HostHeader.tsx` (+ scss + co-located test): hostname title with host-id fallback, online/offline pill (host list's 5-minute predicate via `ui/src/time.ts` helpers), meta row (OS, agent version, last seen, source IP, event count, enrolled date), copyable host id, best-effort fetch that never blocks
- [x] 2.3 Integrate into `ProcessTree.tsx` replacing the raw host-id title link; keep `HostHealthPanel` below
- [x] 2.4 UI tests with spec markers (`host-detail-header/*`) covering the enrolled and degraded cases

## 3. Verification

- [x] 3.1 `go test ./server/detection/...`, integration run with `EDR_TEST_DSN`, `cd ui && npm test`, `task lint:go`, `npm run lint`, `tools/spectrace check --strict`, `openspec validate --all --strict`
- [x] 3.2 Manual QA: rebuild UI, restart dev server, verify the header on a real host page in Chrome (identity from PR 1's check-in, copy button, fallback on a bogus host id)

## 4. Docs

- [x] 4.1 CHANGELOG entry under 0.4.0
