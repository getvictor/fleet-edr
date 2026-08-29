# Catalog surfaces list detections only

## Why

Two registered rules are not detections, and publishing them as such misleads operators on three counts.

`application_control_block` projects a decision the AUTH_EXEC walker already made on the host into the alert stream. It has no detection logic to inspect, its findings borrow the matched app-control rule's id and severity from the event payload rather than carrying its own, and it deliberately maps to no ATT&CK technique because a successful block is the absence of adversary activity rather than an instance of it.

`sensor_recovery_failed` reports that our own automatic repair of a stopped capture provider gave up. Both failure shapes it names point at our software, so it establishes nothing about an adversary.

Publishing either in the rule catalog offers a tuning surface that does not exist, documentation that describes no detection logic, and in the ATT&CK case a coverage figure read during procurement that is inflated by our own crashes.

## What changes

A registered rule may declare itself a non-detection. Non-detections are omitted from the operator-facing catalog surfaces: `GET /api/rules`, `GET /api/attack-coverage`, and the generated `docs/detection-rules.md`.

Nothing about registration, evaluation, or alert persistence changes. Both rules keep firing and keep writing the same alerts. Per-rule mode and severity settings are unaffected, because those are keyed by rule id and never validated against the catalog.

The declaration is opt-in and absent from the `Rule` interface: a detection is the common case and stays the zero-effort default, so a rule that says nothing is treated as a detection.

## Impact

- ATT&CK coverage is unchanged in extent. `T1562.001` was claimed by both `sensor_recovery_failed` and `sensor_tamper`, and remains covered by the latter, so the layer keeps all 13 techniques and only its attribution comment changes.
- `docs/detection-rules.md` loses two entries.
- An operator loses the `/api/rules` path for setting mode or severity on these two. The app-control policy UI already owns the first; the health signal's own surface is tracked separately.
- The `Finding.Title == DisplayName` invariant no longer needs a by-name exemption for `application_control_block`: the exemption now follows from its classification.

## Archive ordering

This delta MODIFIES `Registered rule catalog`, which the in-flight `alert-when-sensor-recovery-gives-up` change also modifies. Archive that change FIRST, or archive them in one pass with this one applied last: the requirement text below is written against the eleven-rule version that change introduces, not against the nine-rule canonical text it replaces.
