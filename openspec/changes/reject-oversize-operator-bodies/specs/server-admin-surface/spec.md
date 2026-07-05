# server-admin-surface (delta: reject oversize operator request bodies)

## ADDED Requirements

### Requirement: Operator mutation endpoints reject oversize request bodies

Operator mutation endpoints that read a JSON request body MUST bound the read at a per-route byte cap and reject a body that exceeds the cap with `413 Request Entity Too Large` and a typed `*.body_too_large` error code, BEFORE attempting to decode it. The server MUST NOT silently truncate an oversize body (which would otherwise surface as a misleading `invalid_json` 400 or be accepted as a partial payload). A body at or below the cap is processed normally.

#### Scenario: Oversize application control mutation body is rejected

- **GIVEN** an authenticated operator POSTs an application-control mutation whose body exceeds the route's cap (16 KiB per-rule, 256 KiB bulk-upsert)
- **WHEN** the server reads the request body
- **THEN** the server returns `413` with `{"error": "application_control.body_too_large"}`
- **AND** the policy is not modified

#### Scenario: Oversize detection config mutation body is rejected

- **GIVEN** an authenticated operator POSTs a detection-config mutation whose body exceeds the 16 KiB cap
- **WHEN** the server reads the request body
- **THEN** the server returns `413` with `{"error": "detection_config.body_too_large"}`
- **AND** the detection-config state is not modified
