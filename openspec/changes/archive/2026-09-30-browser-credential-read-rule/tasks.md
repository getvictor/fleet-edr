## 1. Rule

- [x] 1.1 `credential_browser_store_read` with the owner check, the Apple service skip, and path, team, signing-id and cdhash exclusions
- [x] 1.2 Unit tests, fixtures, the materialization-abandon table, and efficacy scenario `T1555.003-browser-credential-read`
- [x] 1.3 Rule pack file, detection-rules docs and ATT&CK layer regenerated

## 2. Validation

- [x] 2.1 On edr-dev with the credential-store extension, copy a Firefox profile's cookies and confirm the alert
