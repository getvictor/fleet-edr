# Tasks

## 1. Measure what ESF actually delivers, before designing to it

- [x] 1.1 Confirm `NOTIFY_RENAME` is delivered under the existing inverted target-path muting.
- [x] 1.2 Determine which path muting matches on: measured as either, so renames in, within, and out of the set all arrive.
- [x] 1.3 Confirm which `/etc/sudoers.d/` names sudo actually loads, against `sudo -l` rather than the man page alone.
- [x] 1.4 Confirm the visudo false positive (#933) reaches the rule, using the rule's own frozen oracle.

## 2. Collection

- [x] 2.1 Subscribe `NOTIFY_RENAME` on the file-tamper client.
- [x] 2.2 Emit a `file_rename` event carrying pid, source path, and destination path.
- [x] 2.3 Add the payload to `schema/events.json` and the event-type enum.
- [x] 2.4 Correct the header comment's claim that rename would fire on every legitimate visudo edit.

## 3. Detection

- [x] 3.1 Supply the Sigma `file_rename` category with `SourceFilename` and `TargetFilename`.
- [x] 3.2 Narrow the rule's path pattern to the names sudo loads.
- [x] 3.3 Match a rename on its destination.
- [x] 3.4 Update the rule's documented limitations, which currently name this gap as unfixed.

## 4. Verification

- [x] 4.1 Swift tests for the rename payload wire shape, plus the corpus envelope round trip. NOT the emission path: `FileTamperSubscriber` imports EndpointSecurity and is outside the SwiftPM logic target, so the subscription and `handleRename` are verified at the VM layer only.
- [x] 4.2 Go tests for the narrowed pattern, including the `.tmp` and `~` cases, and for the rename match.
- [x] 4.3 Mutation-test the narrowing and the rename match.
- [x] 4.4 Efficacy corpus scenario for the atomic-replace evasion.
- [x] 4.5 VM QA: ESF rename delivery measured on edr-dev with a probe using the production muting setup; the full pipeline (HTTP ingest to alert) exercised against the live lane-B dev server. The re-signed sysext deploy is NOT done, see the PR.
