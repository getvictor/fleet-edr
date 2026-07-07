## Why

Two operator mutation body-readers read the request body with `io.ReadAll(io.LimitReader(r.Body, limit))` (no `+1`), which SILENTLY TRUNCATES a body past the cap. An over-limit request then either fails with a misleading `invalid_json` 400 or, worse, is accepted as a partial-but-valid payload. CodeRabbit flagged this on the app-control handler during the #618 review. The affected readers:

- `server/rules/internal/operator/appcontrol_handler.go` `readAppControlBody` (per-rule 16 KiB / bulk 256 KiB caps).
- `server/rules/internal/operator/detectionconfig_handler.go` `(*DetectionConfigHandler).decode` (16 KiB cap).

The sibling operator handlers (`server/identity/internal/{useradmin,ssoadmin,saadmin}`) already read `limit+1` and return `413` on oversize; this change brings the two outliers in line and documents the operator-surface behavior that had been an undocumented convention.

## What Changes

- Both readers now read `limit+1` and, when `len(body) > limit`, return `413 Request Entity Too Large` with a typed body-too-large error code BEFORE attempting `json.Unmarshal`, so an oversize request is rejected explicitly instead of truncated.
  - app-control: `{"error":"application_control.body_too_large","message":"request body too large"}`.
  - detection-config: `{"error":"detection_config.body_too_large","message":"request body too large"}`.
- Per-route caps are unchanged (app-control 16 KiB per-rule / 256 KiB bulk-upsert; detection-config 16 KiB); only the truncate-vs-reject behavior at the boundary changes.

## Capabilities

### Modified Capabilities

- `server-admin-surface`: the operator mutation endpoints (application-control and detection-config) now reject an oversize request body with `413` and a typed `*.body_too_large` code, rather than silently truncating it.

## Impact

- Wire: a new `413` response with a `*.body_too_large` error code on the app-control and detection-config mutation endpoints. Clients sending within the documented caps are unaffected.
- Code: `appcontrol_handler.go`, `detectionconfig_handler.go` + their tests.
