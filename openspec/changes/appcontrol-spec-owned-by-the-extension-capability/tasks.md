# Tasks

## 1. Record the duplicate finding

- [x] 1.1 Establish that every archived application-control change declared its behaviour in both `endpoint-event-collection` and `extension-application-control`, and that the archive kept one copy of each pair.
- [x] 1.2 Confirm the surviving copy of each pair matches shipped behaviour, so the dropped copy needs no restoration.
- [x] 1.3 Confirm the two detect-mode pairs describe an unbuilt capability tracked by #929 and are not restored by either route.

## 2. Specify the one field that has no producer requirement

- [x] 2.1 State that the `exec` event carries `cdhash` on a Hardened Runtime binary and omits it otherwise, in `Process lifecycle event capture`.
- [x] 2.2 Do not restore the archived claim that the `exec` event carries `leaf_cert_sha256`; the field does not exist.

## 3. Correct the two stale canonical requirements

- [x] 3.1 Remove `Process exec authorization`, whose every clause is already canonical under `extension-application-control` and `Process lifecycle event capture`.
- [x] 3.2 Correct `Block event emission` to the field list both sides of the wire actually use.

## 4. Repair the drifted markers

- [x] 4.1 Add a `Snapshot persistence format is typed` scenario for per-type routing and move the two `ApplicationControlStore` markers onto it.
- [x] 4.2 Add a test of the serialized block-event payload and move the `Block event emission` marker onto it.
- [x] 4.3 Add a test that an `exec` event carries `cdhash` for a hardened binary and omits it otherwise.

## 5. Correct the requirement this change itself added

- [x] 5.1 State both cases where `cdhash` is omitted: a non-hardened process, and a hardened one whose reported hash is all zeros.
- [x] 5.2 Drop the unused `EndpointSecurity` import from `CDHashHex.swift` and move it into the SwiftPM target so the all-zero branch is testable.
- [x] 5.3 Test the all-zero rejection and the last-byte-set companion case.
- [x] 5.4 Pin both new serializer tests to whole-payload literals rather than substring fragments.
