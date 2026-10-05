## 1. Extension

- [x] 1.1 `SnapshotSigning`: map signing information to `CodeSigning`, read the running code by pid, guard against a reused pid with the process start time
- [x] 1.2 `ProcessSnapshotEnumerator` emits the signature with each snapshot exec
- [x] 1.3 Unit tests for the mapping, the reuse guard, and a real read of a running Apple binary

## 2. Server

- [x] 2.1 The graph builder records a later snapshot's signature on an open row that has none and the same path, and nothing else
- [x] 2.2 Integration tests: an unsigned row gains the signature, an existing signature is kept, a different path is not applied

## 3. Validation

- [ ] 3.1 On edr-dev, after the extension restarts, the server's snapshot rows for long-running Apple daemons carry their signatures
