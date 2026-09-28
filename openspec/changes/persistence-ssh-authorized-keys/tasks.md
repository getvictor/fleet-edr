## 1. Rule

- [x] 1.1 Default watched paths `~/.ssh/authorized_keys` and `~/.ssh/authorized_keys2`
- [x] 1.2 `persistence_ssh_authorized_keys` with its detection in the pack file and a writer path exclusion
- [x] 1.3 Unit tests, fixtures and efficacy scenario `T1098.004-ssh-authorized-keys`
- [x] 1.4 Rule pack file, detection-rules docs and ATT&CK layer regenerated

## 2. Validation

- [x] 2.1 On edr-dev, append a key to a user's and root's `authorized_keys` and confirm an alert for each
