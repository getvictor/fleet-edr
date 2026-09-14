# Application control Detect mode

Issue #929. An application-control rule carries an `enforcement` of `PROTECT` or `DETECT`, and the snapshot pushed to each host carries it, but only `PROTECT` has ever meant anything: the extension treats a matched `DETECT` rule as "matched but does not deny" and says nothing. Audit before enforce is how allowlisting and blocklisting get rolled out safely, and without it the only way to learn what a rule would block is to let it block.

The work lands in steps, extension first, so that a `DETECT` rule is never silently inert once an operator can create one. This change starts with the extension.

## What changes

- **A DETECT rule reports what it would have blocked.** When an exec matches a `BLOCK` rule whose enforcement is `DETECT`, the extension lets the exec run and emits an `application_control_would_block` event. The event has the `application_control_block` payload, naming the rule and the identifier that matched. There is no desktop notification, since nothing was blocked.
- **A DETECT rule never weakens enforcement.** The verdict for an exec is the verdict the snapshot reaches with its DETECT rules removed. A DETECT rule does not end the precedence walk, so a lower-precedence PROTECT rule still denies, and the deadline fallback posture still governs an unresolved BINARY hash. An exec that is denied reports no would-block match. When several DETECT rules match, the highest in precedence is reported.
- **An allow that matched a DETECT rule is not cached at the kernel,** so every exec of the binary reaches the handler and is reported.
- **The event schema documents `application_control_would_block`,** and so does the ingest request schema in `docs/api/openapi.yaml`, whose `event_type` list was missing eight of the event schema's values. A test now keeps the two equal, and the canonical envelope requirement names the schema's list instead of an out-of-date copy of it.

## Out of scope for this step

- Setting enforcement from the console or API, the default enforcement for new rules, promoting a rule to PROTECT, and how the server records a would-block match. The server still creates every rule as `PROTECT`, so nothing reaches the new extension path until those land.
- The archived design's regular `exec` event with a `decision` field for a denied exec. A denied exec never replaces the process image, so an `exec` event for it would tell the graph builder the process now runs the blocked binary. It needs its own design.

## Notes for the release archive

The canonical `extension-application-control` purpose paragraph describes Detect mode as deferred. It needs rewording when this change is archived.
