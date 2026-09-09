# Tasks

## 1. Establish what the kernel actually delivers, before designing to it

- [x] 1.1 Confirm `open(O_TRUNC)` emits nothing across CREATE / WRITE / TRUNCATE / RENAME / UNLINK, so `NOTIFY_TRUNCATE` alone cannot close the gap.
- [x] 1.2 Confirm `NOTIFY_TRUNCATE` and `NOTIFY_UNLINK` are delivered under the existing inverted target-path muting.
- [x] 1.3 Determine which bit distinguishes a destructive open, against ESF's fflag rather than `<fcntl.h>`.

## 2. Collection

- [x] 2.1 Subscribe `NOTIFY_TRUNCATE`, `NOTIFY_UNLINK` and `NOTIFY_OPEN`.
- [x] 2.2 Discard every open without `O_TRUNC` inside the extension, so routine policy reads never reach the wire.
- [x] 2.3 Emit `file_truncate` and `file_delete`, and add both payloads to `schema/events.json`.
- [x] 2.4 Correct the class header, which said `NOTIFY_OPEN` was unsubscribed and its case deferred.

## 3. Detection

- [x] 3.1 Add `sudoers_destroyed` as its own rule, mapped to removal rather than to escalation.
- [x] 3.2 Match only the names sudo will load, so an editor removing its own temporary file is not a policy deletion.
- [x] 3.3 Name which destruction happened in the finding, since an emptied file still parses and a removed one does not.
- [x] 3.4 Refuse imported `file_delete` rules as inert, because the export mapping makes them loadable and this agent emits deletions for the sudoers set alone.

## 4. Verification

- [x] 4.1 Rule tests for both event types, the loadable-name boundary, and the technique separation.
- [x] 4.2 Regression fixtures, including the negative case of visudo unlinking its own temporary file.
- [x] 4.3 Property-based round trip for the new wire structs.
- [x] 4.4 Corpus round-trip goldens for both envelopes.
- [x] 4.5 Efficacy corpus scenario carrying no `open` event at all.
- [x] 4.6 Mutation-test the narrowing, the event-type guard, the technique mapping, the description, and the field supply.
- [x] 4.7 VM QA: production `FileTamperSubscriber` run as a standalone ESF client on edr-dev. Three destructive actions produced three events; `sudo true` produced none.
