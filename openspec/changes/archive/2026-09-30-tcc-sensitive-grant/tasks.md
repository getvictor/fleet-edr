## 1. Agent

- [x] 1.1 `appbundle.Path`: a bundle identifier's app through LaunchServices, verified from a LaunchDaemon on edr-dev
- [x] 1.2 `enrich.TccSubjectSigning`: `identity_path` and `identity_code_signing` on `tcc_modify`

## 2. Rule

- [x] 2.1 `tcc_sensitive_grant` with the MDM and platform skips and team, signing-id and path exclusions
- [x] 2.2 Unit tests, a round-trip property test of the payload, fixtures from the captured grant, and efficacy scenario `T1548.006-tcc-sensitive-grant`
- [x] 2.3 Rule pack file, detection-rules docs and ATT&CK layer regenerated

## 3. Validation

- [x] 3.1 On edr-dev, grant Firefox Full Disk Access in System Settings and confirm the alert
