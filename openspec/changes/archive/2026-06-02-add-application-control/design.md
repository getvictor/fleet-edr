## Context

The plan for this work — including the EDR-grade reframe of the original Santa-parity sketch and the multi-phase
roadmap — lives at `claude/policy/plan.md`. This document covers only the architectural decisions for the OpenSpec
change in flight (Phase A); follow-on phases (Lockdown / allowlist / notifications / simulation, then migration
accelerators, then threat-intel ingestion, file-access authorization, and removable-media control) will be proposed
as separate OpenSpec changes.

**Current state:**

- `server/rules/internal/policy/store.go` exposes one `BlocklistPolicy` per deployment with `Paths []string` and
  `Hashes []string` arrays. `server/rules/bootstrap/schema.go` carries the singleton `policies` table. The wire
  command is `set_blocklist`; the extension's `PolicyStore.swift` keeps a `Set<String>` of paths and applies
  AUTH_EXEC denial inline.
- The detection pipeline (`server/detection/internal/rules/`) maps catalog rules to alerts. Blocked execs are
  invisible to that pipeline today.
- ADR-0004 carves the server into five bounded contexts (`identity`, `endpoint`, `rules`, `response`,
  `detection`). The new tables and handlers all live in `rules`. The `application_control_block` event flows
  through the existing event channel that `endpoint` already operates; the `detection` context picks it up the
  same way it picks up exec events.
- The product has not shipped. There are no customers, no migrations, and no compatibility burden. This change
  deletes the existing scaffolding outright.

**Constraints:**

- ESF AUTH_EXEC callbacks have a hard deadline. Decision-engine work on the AUTH path is bounded to map lookups
  plus a constant-time precedence walk; SHA-256 / leaf-cert fetches are off the AUTH path and behind an
  `(inode, mtime)` cache.
- Per ADR-0004, cross-context calls go through `api/` packages only and `arch-go` enforces this. The decision
  pipeline crosses three contexts (extension → endpoint → rules / detection); no new direct cross-context calls
  are introduced.
- Per `CLAUDE.md`, requirement specs MUST state observable behavior and use `SHALL` / `MUST`. Tests follow the
  decision matrix: PBT for invariants, fuzz for untrusted parsers, example-based for wire pinning, integration
  via `testdb/full.Open`.
- macOS 13+ on Apple Silicon. `es_process_t.cdhash`, `team_id`, and `signing_id` are available; leaf-cert SHA-256
  is fetched via `SecCodeCopySigningInformation` against a `SecStaticCode` for the binary.

## Goals / Non-Goals

**Goals:**

- Deliver an Application Control subsystem whose data model and API surface match the EDR-grade structure used
  by CrowdStrike Falcon, SentinelOne Singularity, and Microsoft Defender for Endpoint: named policies, host
  groups, policy → host group assignments, per-rule lifecycle metadata, blocked-exec events integrated with
  the alert pipeline, stable JSON CRUD that SOAR can automate against.
- Cover the six Santa rule identifier types (PATH, BINARY, CDHASH, TEAMID, SIGNINGID, CERTIFICATE) with
  Santa-equivalent precedence, so that a migrating Santa admin's mental model carries over and a future
  importer can translate Santa rules without identifier-level loss.
- Reserve schema room for Phase B's Lockdown / allowlist / detect-mode and for Phase D's threat-intel feeds
  without further migrations.
- Keep the AUTH_EXEC hot path within budget. Add at most a handful of constant-time map lookups; never block
  the AUTH callback on signing-info fetch.

**Non-Goals:**

- ALLOW and SILENT_BLOCK actions; per-policy default-deny (Lockdown); the `DETECT` enforcement semantic; user-
  facing block notifications; the decision cache; failsafe carve-outs against blocking the agent / extension /
  launchd. These all arrive together in the Phase B change.
- Pre-deploy simulation against historical telemetry.
- Santa StaticRules / sync-server-response import. CSV / JSON import. Bulk admin actions beyond bulk-upsert.
- Threat-intel feed ingestion. The schema reserves `source='intel'` and `source_ref` so a later change can drop
  in a feed adapter without altering the rule shape.
- File-Access Authorization, removable-media control, custom IOAs, network containment, real-time response.
  These are separate subsystems with their own ESF subscriptions and / or response channels.
- Cross-platform identifier types (Windows Authenticode publisher, Linux package signer). Schema is shape-ready
  via `rule_type` as a string enum and `payload JSON` for type-specific extensions; the matchers, telemetry,
  and UI work are out of scope.
- CEL expression rules; transitive / compiler-driven allowlists; Santa Standalone mode.

## Decisions

### Subsystem name and bounded-context placement

User-facing name is **Application Control**. The term is shared by SentinelOne, Microsoft Defender, and VMware
Carbon Black; it is unambiguous against our existing custom-detection-rules catalog. Internally, the subsystem
lives under the `rules` bounded context that ADR-0004 already defines, with packages under
`server/rules/internal/appcontrol/` and public types on `server/rules/api/`. The existing detection-rules
catalog under `server/rules/internal/catalog/` is unaffected.

*Alternatives considered:* a new top-level bounded context (`appcontrol/`). Rejected as premature; the
subsystem fits inside `rules` without straining the boundary and the rest of the EDR already knows where
"things related to rules" live.

### Two new capability specs (server + extension), modifications to five existing specs

The Application Control work splits cleanly across the server (table-of-record, REST, validation, audit) and
the extension (signature-tuple extraction, precedence walk, snapshot). The agent's command executor needs a
new command type, the REST API surface grows, the UI grows, the detection-rules engine gains a new alert
source, and the endpoint event-collection capability gains decisioning at AUTH_EXEC time. Hence two new specs
(`server-application-control`, `extension-application-control`) plus deltas against `agent-command-executor`,
`server-rest-api`, `web-ui`, `server-detection-rules-engine`, and `endpoint-event-collection`.

*Alternatives considered:* a single combined `application-control` spec covering server + extension. Rejected
because the repo's existing convention names capabilities by their owning subsystem prefix (`server-*`,
`agent-*`, `extension-*`, `ui-*`); merging into one would diverge from that.

### Data model — four tables in the rules context

Four tables: `app_control_policies`, `app_control_rules`, `host_groups`, `app_control_assignments`. The shape is
the EDR-grade hierarchy (policy is a named ruleset, rules belong to policies, policies are assigned to host
groups). All four tables are seeded; the work to make host groups editable lands in Phase B without a schema
change.

Reserved columns set in Phase A and silent until Phase B:

- `app_control_policies.default_action ENUM('NONE')`: constrained to `NONE` here; the Phase B change extends
  the enum to `('NONE','BLOCK')` to unlock Lockdown.
- `app_control_rules.action ENUM('BLOCK')`: extended to `('BLOCK','ALLOW','SILENT_BLOCK')` in Phase B.
- `app_control_rules.enforcement ENUM('PROTECT','DETECT') DEFAULT 'PROTECT'`: column present, only `PROTECT`
  honored by the engine in Phase A.
- `app_control_rules.source ENUM('admin','imported','intel') DEFAULT 'admin'` and `source_ref VARCHAR`: ready
  for the threat-intel feed change.
- `app_control_rules.expires_at TIMESTAMP NULL`: ready for both intel feed entries and admin-set TTLs.
- `app_control_rules.severity ENUM('low','medium','high','critical') DEFAULT 'medium'`: used immediately
  for alert mapping when a block fires.

*Alternatives considered:*

- One table with `policy_id NULLABLE` and rules implicitly grouped — rejected. The named-policy abstraction
  is the natural unit of versioning, assignment, simulation (Phase B), and audit; making it second-class adds
  no value.
- An EAV / generic-attribute table for per-rule metadata — rejected. The set of columns we need is small,
  bounded, and known. EAV pays for hypothetical extension we don't expect.
- Per-context FKs between policies / rules / assignments — kept. These are intra-context FKs (all four tables
  live in `rules`), which ADR-0004 explicitly permits. ADR-0004's no-cross-context-FK rule does not apply.

### Rule identifier types and precedence

Six identifier types: `CDHASH`, `BINARY`, `SIGNINGID`, `CERTIFICATE`, `TEAMID`, `PATH`. Precedence walked in
that order during decisioning. First match wins. Matches Santa exactly so a migrating Santa admin's mental
model carries over.

`CDHASH` rules only match against processes that run under the Hardened Runtime. This mirrors Santa's
behavior (CDHash on non-hardened processes is not a reliable integrity check because pages are mapped
lazily; tamper detection requires SIP plus Hardened Runtime). A CDHASH rule that nominally targets a
non-hardened binary silently no-ops. The UI surfaces this caveat at rule-create time.

`SIGNINGID` identifiers are prefixed: either `TeamID:bundle.id` (e.g. `EQHXZ8M8AV:com.google.Chrome`) or
`platform:bundle.id` (e.g. `platform:com.apple.curl`) for Apple platform binaries. This is also Santa's
format; the importer in the Phase C change will accept Santa's wire form unchanged.

*Alternatives considered:* a unified `IDENTIFIER` rule type with `payload.type` discriminator. Rejected for
two reasons: every decision-engine evaluator and every validator would still need a per-type branch; and the
indexable column for fast lookup needs to be of fixed shape per type (CDHash is 40 hex, BINARY/CERTIFICATE
are 64 hex, TeamID is 10 chars, SigningID is TeamID-prefixed dotted-id, PATH is an absolute path). A typed
`rule_type` column with a flat `identifier` column lets MySQL index `(policy_id, rule_type, identifier)` for
the dedup unique-key without ambiguity.

### Decision engine on the extension hot path

The extension keeps a typed snapshot: one `Dictionary<String, RuleDecision>` per rule type, plus a separate
`Dictionary<String, RuleDecision>` for PATH. AUTH_EXEC builds a target tuple and walks the precedence order
returning on first hit. The walk is six map lookups in the worst case (one lookup per identifier type plus
PATH); five of those keys are short fixed-length strings (CDHash, hashes, TeamID, SigningID, leaf-cert hash)
so the map cost is ~hundreds of nanoseconds at most. Aggregate budget for the decision step is well below
1 µs at p99 and stays inside the AUTH_EXEC deadline.

Lazy fetches:

- `file_sha256` is computed on first decision and cached by `(inode, mtime)`. If absent at decision time, the
  BINARY rule type is skipped for that exec; the cache fills for next time. This matches today's behavior in
  the existing telemetry pipeline.
- `leaf_cert_sha256` is fetched via `SecCodeCopySigningInformation` against a `SecStaticCodeCreateWithPath`
  handle. Same `(inode, mtime)` cache. Same silent-miss-on-first-exec behavior. The fetch happens off the
  AUTH callback and never blocks it.

The snapshot is rebuilt and atomically swapped on receipt of a `set_application_control` command. The current
snapshot file format is replaced with a typed JSON snapshot keyed by `(rule_type, identifier)`; old
`policy.json` is deleted on first decode.

*Alternatives considered:*

- A bloom-filter front for the rule maps. Rejected; with the rule counts we expect (single-digit thousands
  at the high end) a hash-map is fast enough and far simpler.
- Synchronous signing-info fetch on AUTH. Rejected; the fetch cost is variable (cache hits in
  `Security.framework` make it fast, cold lookups are not). Bounding the AUTH deadline with a sync external
  call is fragile.
- An in-extension cache by binary path rather than `(inode, mtime)`. Rejected — same path can be a different
  binary if the file is replaced.

### Block-event → alert pipeline integration

When the decision engine returns `BLOCK`, the extension denies the exec and emits an event of kind
`application_control_block` carrying the matched rule's identity, the binary identifiers it matched on, the
matched rule's severity, and the standard process and ancestry fields. The server-side detection-rules engine
maps this event to an alert with `source='application_control'`. Existing alert dedup keys
(`host_id, rule_id, process_id`) extend to the new source unchanged; the operator's alert view filters and
groups on the new source value.

This is the EDR-grade move that justifies wiring it in Phase A rather than Phase B: if Phase A ships blocks
as a silent side-channel and Phase B then bolts on alert integration, the alert ingester would be refactored
twice. Doing the wiring once now avoids that.

*Alternatives considered:*

- Emitting a generic "exec verdict" event for every AUTH decision (allow and block alike). Considered for
  future-proofing the Phase B DETECT-mode case but skipped here because Phase A only blocks; the verdict
  event becomes useful when DETECT-mode allows-but-records the would-be decision, which is Phase B's job.
  The extension change to add an allow-side verdict event is additive and does not require schema changes.
- Treating blocks as a new alert type rather than a new alert source. Rejected; alert *types* are the rule
  identities (the rule that fired), and a blocked exec carries the rule that fired. Alert source is the
  correct dimension to discriminate "which subsystem produced this alert".

### REST surface and authentication

`/api/v1/app-control/` is the surface. Resource paths are conventional REST; bulk-upsert is exposed as a
sibling action endpoint (`POST /policies/{id}/rules:bulkUpsert`) rather than as a magic PUT body so SOAR
clients can pick it explicitly. Authentication uses the existing operator session cookie + CSRF token from
`POST /api/session`; the host bearer-token issued at `/api/enroll` is irrelevant to this surface (agents do
not author rules).

All shapes are versioned under `/api/v1/`. This is the contract our customers will automate against.

*Alternatives considered:* an `/api/policy/v2/` namespace continuing the existing pattern. Rejected; the
versioning convention for new surfaces should start at `/api/v1/` and grow forward. Coexistence with the
existing unversioned routes is fine.

### Decision-event wire shape and event schema

A blocked exec emits `application_control_block` with required fields:

- `policy_id`, `policy_version`, `rule_id`, `rule_type`, `rule_identifier` — identifying the rule.
- `matched_identifier` — the actual value from the process that hit the rule (e.g. the CDHash that matched).
- `severity` — copied from the rule.
- `custom_msg`, `custom_url` — copied from the rule, may be null.
- `process`, `ancestry` — the standard event fields all exec-related events carry.

Existing exec events grow optional `cdhash` and `leaf_cert_sha256` fields. They are optional because the
lazy-cache miss path will silently omit them; the server is tolerant of their absence.

*Alternatives considered:* embedding the full rule in each block event. Rejected; the rule may change after
the block fires and the alert needs to reflect the rule as it was at decision time. The five identifying
fields suffice; downstream views resolve the rule on demand.

### Failsafes — explicitly deferred to Phase B

Failsafe carve-outs (the policy must not be able to block the agent, the system extension, the host app, or
`launchd`) are a Phase B concern. In Phase A the only enforced action is `BLOCK`; an admin who installs a
rule that targets the agent will brick the host. That is acceptable in Phase A only because Phase A has no
default-deny — every block requires an explicit rule, so an admin can only brick themselves by deliberately
authoring a rule that targets us. Phase B introduces Lockdown (default-deny), at which point failsafes
become non-optional.

The Phase B change will add failsafes as a server-pushed list (not a hardcoded extension constant) so they
are auditable and updatable without an agent re-release. The schema and spec change required is small and
not in scope here.

## Risks / Trade-offs

- **AUTH_EXEC deadline pressure on first-exec-after-boot** → six map lookups stay inside budget; the
  signing-info fetch is off the AUTH path and lazy-cached, so the worst case is "first exec of a never-seen
  binary's CERTIFICATE rule silently misses, the cache fills, second exec catches it". Documented behavior;
  not a bug.
- **Admin self-block in Phase A** → an admin can author a BLOCK rule that targets the agent or extension and
  brick the host. Mitigation in Phase A is documentation only; the failsafes ride in with Phase B because
  they're naturally a default-deny problem. Phase A admins have to be careful with self-targeting rules and
  recover via the same out-of-band mechanism (signed config-profile override) Phase B will codify.
- **Detection-pipeline ingest volume** → an existing-customer-with-a-broad-blocklist scenario does not apply
  (pre-release), but the new alert source can still produce volume when an admin author a permissive PATH
  rule against a high-frequency exec target. Mitigation: alerts default to severity `medium`; the alert view
  ships with a default grouping of "collapse repeats per (rule_id, host_id, hour)" the same way our existing
  alert grouping works.
- **Cross-platform regret** → schema columns are typed for current macOS identifier shapes (PATH, TeamID
  format, SigningID format, hash lengths). Adding `AUTHENTICODE_PUBLISHER` later requires the validator to
  understand a new identifier shape but does not require a table migration since `rule_type` is a string enum
  and `identifier` is a `VARCHAR` of generous length. Documented as a Phase D arc.
- **Signing-info cache invalidation** → cache keyed by `(inode, mtime)` is robust against replaced files but
  not against files modified in-place (mtime unchanged). The macOS code-signing apparatus already rejects
  in-place modifications of signed binaries; the residual risk is unsigned PATH-matched binaries modified
  in-place, which is acceptable.
- **Rule explosion in the snapshot** → snapshot size scales O(rules). At ten thousand rules the snapshot is
  under 1 MB JSON, which is fine for atomic-write-then-rename. If we materially exceed that, the snapshot
  format switches to a length-prefixed binary; tracked as a follow-on optimization, not a Phase A concern.
- **Audit-event volume** → per-rule audit events are emitted on every create / edit / delete. Bulk-upsert
  emits one audit event per logical operation rather than one per touched rule, keeping write amplification
  bounded. The decision is reflected in the spec.

## Migration Plan

No customer-facing migration. The product has not shipped.

**Deploy:**

1. Apply the bootstrap schema change (drop `policies`; create the four new tables; seed `Default` policy and
   `all-hosts` group).
2. Land the server packages, REST handlers, agent command type, extension snapshot rewrite, and UI in the PR
   order listed in `tasks.md`.
3. Existing test databases re-bootstrap from `seed/db.sql`.

**Rollback** (pre-release):

- The change is a single multi-PR set across server, agent, extension, schema, and UI. Rolling back means
  reverting that PR set in git. There is no compatibility shim and none is added.
- The bootstrap schema is versioned; rollback re-creates the old singleton `policies` table.
- `schema/events.json` reverts to the prior shape removing `application_control_block` and the optional
  `cdhash` / `leaf_cert_sha256` fields on exec events. Server ingestion is tolerant of unknown fields, so a
  partial revert leaves the server able to accept old-shape events without code change.
- Persisted host token is not touched.

## Open Questions

- None blocking. The reframed plan at `claude/policy/plan.md` resolved every open design question on the
  prior draft and the user has accepted those recommendations. Re-derived here so reviewers do not have to
  cross-reference: name = "Application Control"; host-groups schema-only in Phase A; block-event integration
  in Phase A; per-policy `default_action`; per-rule `enforcement`; modal-style block notification in Phase B;
  CDHash hardened-runtime requirement mirrored from Santa; simulation in Phase B.
