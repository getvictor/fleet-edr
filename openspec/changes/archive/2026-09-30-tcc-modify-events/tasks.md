## 1. Extension and wire

- [x] 1.1 Subscribe to `NOTIFY_TCC_MODIFY` and emit `tcc_modify`, with the SDK's enums spelled by `TccNames`
- [x] 1.2 `tcc_modify` in `schema/events.json` and the fake agent's schema sample
- [x] 1.3 Unit tests for the names and the payload's wire keys

## 2. Validation

- [x] 2.1 On edr-dev, a Developer Tools change by `spctl` and a reset by `tccutil` were uploaded as `tcc_modify` (modify by syspolicyd, then delete by tccutil on behalf of the SSH session)
- [x] 2.2 Capture a grant made in System Settings (edr-dev, 2026-09-29): adding Firefox to Full Disk Access arrived as `modify`, right `allowed`, reason `user_set`, service `SystemPolicyAllFiles`, instigated by `com.apple.settings.PrivacySecurity.extension`
- [ ] 2.3 Before RC, on edr-qa (SIP on) with a signed build, confirm `tcc_modify` events are uploaded

## 3. Agent

- [x] 3.1 The agent adds the app's path, through LaunchServices for a bundle identifier, and its code signing (#1185 part 2)
