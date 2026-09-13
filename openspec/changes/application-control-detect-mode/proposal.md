# Application control Detect mode

Issue #929. An application-control rule carries an `enforcement` of `PROTECT` or `DETECT`, and the snapshot pushed to each host carries it, but only `PROTECT` has ever meant anything: the extension treats a matched `DETECT` rule as "matched but does not deny" and says nothing. Audit before enforce is how allowlisting and blocklisting get rolled out safely, and without it the only way to learn what a rule would block is to let it block.

The work lands in steps, extension first, so that a `DETECT` rule is never silently inert once an operator can create one.

## What changes

### Extension

- **A DETECT rule reports what it would have blocked.** When an exec matches a `BLOCK` rule whose enforcement is `DETECT`, the extension lets the exec run and emits an `application_control_would_block` event. The event has the `application_control_block` payload, naming the rule and the identifier that matched. There is no desktop notification, since nothing was blocked.
- **A DETECT rule never weakens enforcement.** The verdict for an exec is the verdict the snapshot reaches with its DETECT rules removed. A DETECT rule does not end the precedence walk, so a lower-precedence PROTECT rule still denies, and the deadline fallback posture still governs an unresolved BINARY hash. An exec that is denied reports no would-block match. When several DETECT rules match, the highest in precedence is reported.
- **An allow that matched a DETECT rule is not cached at the kernel,** so every exec of the binary reaches the handler and is reported.
- **The event schema documents `application_control_would_block`,** and so does the ingest request schema in `docs/api/openapi.yaml`, whose `event_type` list was missing eight of the event schema's values. A test now keeps the two equal, and the canonical envelope requirement names the schema's list instead of an out-of-date copy of it.

### Server

- **Enforcement is set on create and changed on update.** `POST /api/v1/app-control/policies/{id}/rules` accepts `enforcement`, and `PATCH /api/v1/app-control/rules/{id}` changes it, which is how a rule is promoted. Any other value is a 400. The change bumps the policy version, reaches hosts, and is audited with the rule's enforcement.
- **A request without enforcement still creates a PROTECT rule.** The archived design made DETECT the default for new rules. Automation written against earlier releases creates rules that block, and a changed default would quietly turn those into rules that only record. The console, which an operator reads before saving, is where Detect can be the default.
- **A would-block match is kept as a monitor record, not an alert.** A new projection rule, `application_control_would_block`, maps the event the way `application_control_block` maps a block, and declares monitor. Its records sit under the application-control rule's id, so the monitor-records page for `app_control:<id>` lists what the rule would have blocked. The archived design raised these as alerts with a `would_block` subtype; monitor records postdate it and are the product's existing answer to "what would this rule have done", with no triage, no webhook delivery and their own retention.
- The two shared requirements in `server-detection-rules-engine` are restated identically in `sensor-recovery-as-host-health`, which is also in flight, so the release archive keeps both changes' text whichever it applies last.

## Out of scope

- The console: an enforcement selector when adding a rule, promoting a rule from the policy page, and reaching a rule's monitor records from it.
- Enforcement on `rules:bulkUpsert`, which keeps creating PROTECT rules.
- The archived design's regular `exec` event with a `decision` field for a denied exec. A denied exec never replaces the process image, so an `exec` event for it would tell the graph builder the process now runs the blocked binary. It needs its own design.

## Notes for the release archive

The canonical `extension-application-control` purpose paragraph describes Detect mode as deferred. It needs rewording when this change is archived.
