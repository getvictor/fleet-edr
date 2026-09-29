## 1. Rule

- [x] 1.1 `trusted_root_certificate` with its detection in the pack file
- [x] 1.2 Unit tests, fixtures and efficacy scenario `T1553.004-trusted-root-certificate`
- [x] 1.3 Rule pack file, detection-rules docs and ATT&CK layer regenerated

## 2. Validation

- [x] 2.1 On edr-dev, trust a self-signed test certificate with `security add-trusted-cert`, confirm the alert, and remove the trust setting
