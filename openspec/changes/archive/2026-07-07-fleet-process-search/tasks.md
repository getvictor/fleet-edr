## 1. Types + cursor

- [x] 1.1 `server/detection/api`: `ProcessSearchFilter` (host_id, path, hash, uid, time range, exit_reason, signing) and `ProcessSearchResult` (rows []Process, next_cursor string, total_matched int64)
- [x] 1.2 Opaque cursor encode/decode (base64url of `fork_time_ns:id`), with a decode error path; unit test round-trip + malformed

## 2. Store query

- [x] 2.1 Migration: index `(fork_time_ns, id)` for the keyset scan and index on `sha256`
- [x] 2.2 `Store.SearchProcesses(ctx, filter, cursor, limit)` in `server/detection/internal/mysql/processes.go`: AND-composed WHERE in SQL, signing derived from `code_signing` JSON (CS_ADHOC bit / team_id / is_platform_binary / null), keyset `(fork_time_ns, id) < (?, ?)` ORDER BY DESC LIMIT, plus a `COUNT(*)` companion for `total_matched`
- [x] 2.3 PBT: paginating the full set with any page size reproduces the unpaginated set, in order, no dupes (spec marker `keyset-pagination-is-stable-and-complete`); integration tests for each filter + compose + host scoping (spec markers `filters-compose-across-hosts`, `hash-search-spans-hosts`, `host-filter-scopes-to-one-host`)

## 3. Handler

- [x] 3.1 `process_search_handler.go`: `ProcessSearchReader` seam + `SetProcessSearch` + `registerSearchRoutes` (`GET /api/search/processes`), `ActionProcessRead` fleet gate, parse + validate params, 400 on malformed cursor; bootstrap wiring
- [x] 3.2 Handler tests: filter parsing, empty result, malformed cursor 400, unwired 503, authz deny (spec marker `malformed-cursor-is-rejected`)

## 4. Verification

- [x] 4.1 `go test ./server/detection/...` + integration with `EDR_TEST_DSN`, `go vet -tags integration ./...`, `task lint:go`, `tools/spectrace check --strict`, `openspec validate --all --strict`
- [x] 4.2 Manual QA on the dev server: curl `/api/search/processes` across the seeded multi-host data, verify filter composition, cursor paging, and total_matched

## 5. Docs

- [x] 5.1 CHANGELOG entry under 0.4.0
