# Application control Detect mode

Issue #929. An application-control rule carries an `enforcement` of `PROTECT` or `DETECT`, and the snapshot pushed to each host carries it, but only `PROTECT` has ever meant anything: the extension treats a matched `DETECT` rule as "matched but does not deny" and says nothing. Audit before enforce is how allowlisting and blocklisting get rolled out safely, and without it the only way to learn what a rule would block is to let it block.

The work lands in steps, extension first, so that a `DETECT` rule is never silently inert once an operator can create one.

## What changes

### Extension

- **A DETECT rule reports what it would have blocked.** When an exec matches a `BLOCK` rule whose enforcement is `DETECT`, the rule does not block it, and when the exec is allowed the extension emits an `application_control_would_block` event. The event has the `application_control_block` payload, naming the rule and the identifier that matched. There is no desktop notification, since nothing was blocked.
- **A DETECT rule never weakens enforcement.** The verdict for an exec is the verdict the snapshot reaches with its DETECT rules removed. A DETECT rule does not end the precedence walk, so a lower-precedence PROTECT rule still denies, and the deadline fallback posture still governs an unresolved BINARY hash. An exec that is denied reports no would-block match. When several DETECT rules match, the highest in precedence is reported.
- **An allow that matched a DETECT rule is not cached at the kernel,** so every exec of the binary reaches the handler and is reported.
- **The event schema documents `application_control_would_block`,** and so does the ingest request schema in `docs/api/openapi.yaml`, whose `event_type` list was missing eight of the event schema's values. A test now keeps the two equal, and the canonical envelope requirement names the schema's list instead of an out-of-date copy of it.

### Server: would-block matches are monitor records

- **A would-block match is kept as a monitor record, not an alert.** A new projection rule, `application_control_would_block`, maps the event the way `application_control_block` maps a block, and declares monitor. Its records sit under the application-control rule's id, so the monitor-records page for `app_control:<id>` lists what the rule would have blocked, with the rule's severity. The archived design raised these as alerts with a `would_block` subtype. Monitor records postdate it and are the product's existing answer to "what would this rule have done": no triage, no webhook delivery, their own retention. Application-control audit modes elsewhere (Windows Defender Application Control audit mode, Santa monitor mode) likewise report would-be blocks for review rather than raising alerts, because a broad rule in audit can match every exec of a common binary.
- The record's subject is the process that attempted the exec, as a block alert's is, so a record and the alert it becomes after promotion deduplicate the same way.
- The two shared requirements in `server-detection-rules-engine` are restated identically in `sensor-recovery-as-host-health`, which is also in flight, so the release archive keeps both changes' text whichever it applies last.

### Enforcement is a required choice

- **Every rule names its enforcement; there is no default.** Rule create and every item of `rules:bulkUpsert` require `enforcement`, and a request without it is a 400. PROTECT blocks and DETECT only records, and a rule that silently took either would be wrong for the caller who meant the other: a PROTECT default turns a rule meant to be watched into one that blocks production, and a DETECT default turns a rule meant to stop a known-bad binary into one that only records it. CrowdStrike's IOC management and Microsoft Defender's custom indicators both make the action a required choice for the same reason. The archived design defaulted new rules to DETECT. API clients that omitted the field now get a 400, called out as an upgrade note.
- **Update and re-upsert change it.** `PATCH /api/v1/app-control/rules/{id}` accepts `enforcement`, and a bulk upsert that updates an existing rule sets it. Any change bumps the policy version, reaches hosts, and is audited with the rule's enforcement.
- **The console asks.** The Add rule and Paste many dialogs present Detect and Protect with neither selected, and saving waits for a choice.
- The database column keeps its `DEFAULT 'PROTECT'`. Dropping it would not help: MySQL gives a `NOT NULL` ENUM column its first value when an insert omits it, default or not, so the store's validation is the guard.

## Out of scope for these steps

- Promoting a rule from the console, and a rule's would-block impact where the promote decision is made (executions and hosts it would have blocked, with a link to its monitor records). They come next.
- The archived design's regular `exec` event with a `decision` field for a denied exec. A denied exec never replaces the process image, so an `exec` event for it would tell the graph builder the process now runs the blocked binary. It needs its own design.

## Notes for the release archive

The canonical `extension-application-control` purpose paragraph describes Detect mode as deferred. It needs rewording when this change is archived.
