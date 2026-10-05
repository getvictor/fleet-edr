## 1. Extension

- [x] 1.1 `SnapshotSigning`: map signing information to `CodeSigning`, read the running code by pid, guard against a reused pid with the process start time
- [x] 1.2 `ProcessSnapshotEnumerator` emits the signature with each snapshot exec
- [x] 1.3 Unit tests for the mapping, the reuse guard, and a real read of a running Apple binary

## 2. Server

- [x] 2.1 The graph builder records a later snapshot's signature on an open row that has none and the same path, and nothing else
- [x] 2.2 Integration tests: an unsigned row gains the signature, an existing signature is kept, a different path is not applied

## 3. Validation

- [x] 3.1 On edr-dev (build 71), the startup snapshot's exec events carry signatures: 398 of 400 after the extension restarted
- [ ] 3.2 On rc.3 (dogfood, after the upgrade), the open `mds` row carries its signature and no `credential_browser_store_read` is raised for Spotlight
