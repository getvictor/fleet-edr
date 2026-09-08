# Retire the vestigial open-flag fields

## Why

`sudoers_tamper` read two engine-computed fields about an `open(2)` flags value: `WriteIntent` (did the open carry write access) and `MutatingOpen` (did it carry a content-changing flag, used to suppress sudo's `LOCK_EX` flock). Both have been inert since #301, and #801 exists to retire them deliberately rather than leave two masks that look pointless.

They are inert because since #301 there is exactly one emitter of `open` events: `FileTamperSubscriber` re-emits ESF `NOTIFY_CREATE` and `NOTIFY_WRITE` on sudoers paths with a **constant synthetic flag set** (1537). Against a constant, write access is always set and the mutating bits are always set, so the first test always passed and the second could never fire.

They cannot be made real. Real `open(2)` flags need a broad `NOTIFY_OPEN` subscription, and ADR-0008 drops it on two grounds: ESF silently ignores per-event-type muting for `NOTIFY_OPEN`, so it cannot be scoped, and in the ADR's own words it "is not how top EDRs collect file telemetry".

## What changes

The lock-versus-modification decision moves from the rule into the field supplier. `TargetFilename` is now supplied only for an open that carries write access **and** a content-changing flag, which is what makes the field mean what Sigma's `file_event` category says it means: a completed creation or modification.

`sudoers_tamper` becomes a path test alone, and with it plain Sigma (`portable: standard`) rather than a rule needing two fields this engine computes.

Moving the decision rather than deleting it is deliberate. The suppression is not cosmetic: a fixture records 30 `sudoers_tamper` alerts on one host in 15 minutes when it was absent, measured during rc.6 QA on edr-qa. Deleting the fields without moving the decision would reintroduce that on any agent predating #301, which still sends real flags and which nothing yet forces to upgrade (#88).

## Impact

- No behaviour change on any agent shipping today. The synthetic constant carries both halves of the new gate, so every event that produced a finding still does.
- On an agent predating #301, one shape changes: a writer other than sudo that opens a sudoers file write-mode with no content-changing flag and then writes is no longer reported. The rule's suppression named sudo alone; the adapter's gate does not distinguish writers. That is the cost of moving the decision, and it buys the rule being plain Sigma.
- `WriteIntent` and `MutatingOpen` are removed from the taxonomy and from the exporter's computed-field set. No imported rule reads them.

## Out of scope

The rule's largest gap is unchanged and is not this proposal's subject: an atomic-rename write (write a temp file, rename it onto `/etc/sudoers`) is still missed, because the extension does not subscribe to `NOTIFY_RENAME` even though ADR-0008's decision includes it. Tracked separately.
