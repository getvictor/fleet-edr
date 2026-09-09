# Restore the alerts list's source filter to the spec

## Why

`GET /api/alerts` accepts a `source` query parameter and has since application control shipped. `operator/handler.go` reads it (`Source: r.URL.Query().Get("source")`) and `mysql/alerts.go` applies it (`query += " AND source = ?"`) on both the list and count paths.

`server-rest-api/Filterable alerts list` does not mention it. It says the response is "filterable by host identifier, status, severity, and linked process identifier", and stops there.

The filter was specified by the archived `2026-06-02-add-application-control-detect-mode` change, as `Alerts list filters by source and subtype`. The archive dropped that requirement and canonical never gained the half of it that shipped, so a working, operator-facing filter has been undocumented since.

This is the third real loss the #905 audit has turned up, and it has the same shape as the others: the archived change bundled something that shipped with something that did not, and losing the whole requirement lost the half that works.

## What changes

`source` is added to the filter list, with a scenario, and the conjunctive-combination rule is stated because the existing requirement implied it through one example rather than saying it.

The two existing scenarios are kept verbatim; both carry markers in `server/detection/internal/tests/integration_test.go`.

## What is deliberately NOT restored

The archived requirement's other half is the `subtype` filter, which separates blocks from would-blocks. There are no subtypes: nothing persists or serves one, because Detect mode was never built. That half belongs to #929.

The archived requirement is NOT recorded in `openspec/archive-verify-exceptions.yaml`, and deliberately so. Exceptions match per requirement, so an entry pointing at the restored survivor would also classify the unbuilt subtype findings as surviving under it, which is false. It stays outstanding until #952 settles how a requirement whose findings are part-surviving and part-unbuilt can be classified honestly.

## Impact

- Affected specs: `server-rest-api`
- Affected code: none
- No behaviour changes. The filter already works; only its description was missing.
