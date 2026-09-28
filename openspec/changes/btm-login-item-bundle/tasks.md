## 1. Wire

- [x] 1.1 Add `app_url` to `btm_launch_item_add` in `schema/events.json` and the extension's payload

## 2. Agent

- [x] 2.1 Resolve a relative item path against `app_url`
- [x] 2.2 Sign-check a login item's helper bundle when there is no executable path
- [x] 2.3 Unit tests from the captured login-item shape

## 3. Validation

- [ ] 3.1 Register a login item on the edr-dev VM and confirm the uploaded event carries the resolved path and the bundle's signing
