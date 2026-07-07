## Context

Processes live in the detection context's MySQL `processes` table; the operator read paths (tree, detail, host, histogram) all query it through `mysql.Store`, while network/DNS correlation is delegated to the ClickHouse archive. `processes` has only host-scoped or single-column indexes today, none supporting a fleet-wide scan ordered by `fork_time_ns` or filtered by path/hash. The audit log is the only keyset-pagination prior art (single-column `id < ?`, plain int64 cursor, no server-emitted next cursor).

## Goals / Non-goals

**Goals:**

- Fleet-wide from the start: `host_id` is one optional filter, not a separate surface.
- Filters compose in SQL; pagination is keyset (stable under concurrent inserts), not offset.
- `total_matched` for the filtered set so the UI can show "N results".

**Non-goals:**

- No `has_network` filter, no connection/DNS classes, no UI (later PRs of #582).
- No free-text query language; filters are typed params (the UI builds them from chips).
- No arbitrary sort in v1: newest-first is the only order (the natural triage default and the keyset the index supports).

## Decisions

- **Compound keyset `(fork_time_ns, id)` DESC.** `fork_time_ns` is not unique (batched execs share a fork instant), so the row `id` breaks ties and guarantees a total order; the cursor carries both. Row-value comparison `(fork_time_ns, id) < (?, ?)` expresses "strictly older than the last row seen", stable when new rows arrive at the head between pages. Chosen over offset because a fleet-wide feed takes inserts constantly and offset would skip/repeat rows.
- **Opaque cursor** = base64url of `"<fork_time_ns>:<id>"`. Opaque so the client treats it as a token (the audit log leaked a raw id; a fresh convention here keeps the pagination contract server-owned), but trivially decodable server-side. A malformed cursor is a 400, not a silent full scan.
- **`total_matched` is a `COUNT(*)` with the same WHERE minus the cursor and limit.** One extra indexed query per search; acceptable for the pilot scale, and the honest number the "N results" UI needs. Documented as the one unbounded-ish query, bounded in practice by the filter predicate.
- **`signing` filter derived in SQL** to match the UI's verdict vocabulary: `unsigned` = `code_signing IS NULL`; `ad-hoc` = the CS_ADHOC bit in the JSON `flags`; `platform` = `is_platform_binary` true; `developer-id` = non-empty `team_id`; `signed` = a signing id present with none of the above. One CASE-like predicate per requested class, so the wire vocabulary and the node-tooltip verdict stay aligned.
- **Two new indexes**: `(fork_time_ns, id)` for the keyset scan (the sort key), and `sha256` for the "all execs of this hash" pivot that is the search's most common entry. Path/uid/exit_reason apply as residual predicates on the scanned rows; adding an index per optional filter is premature before we see real query mixes.
- **Reader-seam handler** (`ProcessSearchReader` + `SetProcessSearch` + `registerSearchRoutes`), the same co-located route+gate+handler pattern as host-detail/histogram, gated on `ActionProcessRead` with a fleet-scoped `Resource{Type:"process"}` (no host id), mirroring `handleListHosts`.

## Risks / Trade-offs

- [`total_matched` COUNT on a huge unfiltered fleet search] -> bounded by the pilot's 10-500 host scale and the time-range filter the UI always sends; if it ever bites, cap it (COUNT over a LIMIT) and return `total_matched_capped`. Not pre-optimized.
- [New indexes on a large `processes` table] -> additive, online-addable; the migration adds them with no data change.
- [Signing-verdict SQL drifts from the TS `deriveSigningVerdict`] -> both reference the same CS_ADHOC/team_id/platform rules; a shared comment cites the other. A follow-up could pin them with a cross-language fixture.
