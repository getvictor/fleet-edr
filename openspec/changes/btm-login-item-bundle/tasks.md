## 1. Wire

- [x] 1.1 Add `app_url` to `btm_launch_item_add` in `schema/events.json` and the extension's payload

## 2. Agent

- [x] 2.1 Resolve a relative item path against `app_url`
- [x] 2.2 Sign-check a login item's helper bundle when there is no executable path
- [x] 2.3 Sign-check an app item's bundle, which likewise has no executable path
- [x] 2.4 Unit tests from the captured login-item and app shapes

## 3. Validation

- [x] 3.1 Register a login item on the edr-dev VM and confirm the uploaded event carries the resolved path and the bundle's signing
- [x] 3.2 Add an app through the legacy login-items list on edr-dev and confirm the uploaded event carries the app bundle's signing
