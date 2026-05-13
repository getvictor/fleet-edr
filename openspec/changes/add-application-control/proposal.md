# Application Control: replace the legacy singleton blocklist

## Why

The EDR competes against CrowdStrike Falcon, SentinelOne Singularity, Microsoft Defender for Endpoint, and VMware
Carbon Black Cloud. Every one of those products ships an application-control surface with named policies, host-group
scoping, detect-vs-protect modes, rule lifecycle (source / severity / expiration), and blocked-exec events that flow
into the unified detection pipeline. We currently ship a singleton blocklist with two textareas: paths and SHA-256
hashes. That is enough for a laptop demo, not enough for a pilot — and not enough to convince a customer who runs
Santa today to migrate, since Santa already covers five identifier types, allowlists, and Lockdown.

This change replaces the singleton blocklist with the EDR's Application Control subsystem. Phase A delivers the
data model, the six rule identifier types from Santa (PATH, BINARY, CDHASH, TEAMID, SIGNINGID, CERTIFICATE), the
precedence-aware decision engine on the extension hot path, the REST surface, the UI, and the integration of
blocked execs into the alert pipeline. Allowlists, Lockdown (default-deny), block notifications, and pre-deploy
simulation arrive in a follow-on change once the chassis is in place. Threat-intel feed ingestion, file-access
authorization, removable-media control, and cross-platform identifier types are deferred to their own changes; the
schema introduced here accommodates them without further migration.

The product has not shipped its first release. This change deletes the existing scaffolding outright rather than
preserving a compatibility window. No data migrations, no agent capability negotiation, no deprecated endpoints.

## What Changes

- **BREAKING (pre-release only):** delete the singleton `policies` table, the `blocklist` JSON column, the
  `set_blocklist` agent command, the `GET /api/policy` and `PUT /api/policy` endpoints, the
  `PolicySender` interface and `PolicyStore.swift` snapshot format, and the `PolicyEditor.tsx` UI screen. None of
  this is in customer hands; the singleton model is the wrong shape for the EDR-grade subsystem this change
  introduces.
- Add the **Application Control** subsystem under the existing `rules` bounded context. Four tables:
  `app_control_policies` (named, versioned ruleset per tenant), `app_control_rules` (one row per rule),
  `host_groups` (membership criteria), `app_control_assignments` (policy → host group, with priority for future
  conflict resolution). Built-in `all-hosts` group and a `Default` policy are seeded per tenant.
- Add six rule identifier types with fixed precedence walked CDHASH → BINARY → SIGNINGID → CERTIFICATE → TEAMID
  → PATH:
  - `CDHASH` — 40 hex characters, matched only against processes that run under Apple's Hardened Runtime.
  - `BINARY` — SHA-256 of the executable, 64 hex characters.
  - `SIGNINGID` — `TeamID:bundle.id` or `platform:bundle.id` for Apple platform binaries.
  - `CERTIFICATE` — SHA-256 of the leaf signing X.509 certificate, 64 hex characters.
  - `TEAMID` — 10-character Apple Developer Team ID.
  - `PATH` — absolute filesystem path in macOS canonical form.
- Per-rule columns set in this change with semantics activated either now or in the follow-on:
  - `action ENUM('BLOCK')` — Phase A enforces blocks only. `ALLOW` and `SILENT_BLOCK` arrive with the
    Lockdown change.
  - `enforcement ENUM('PROTECT','DETECT') DEFAULT 'PROTECT'` — column present in Phase A; only `PROTECT` is
    honored by the decision engine. `DETECT` (audit-only) wires in with the Lockdown change.
  - `enabled BOOL`, `custom_msg`, `custom_url`, `comment`, `severity ENUM('low','medium','high','critical')`,
    `source ENUM('admin','imported','intel') DEFAULT 'admin'`, `source_ref`, `expires_at NULLABLE`.
- Per-policy `default_action ENUM('NONE')` column, constrained to `NONE` in Phase A. Lockdown change unlocks
  `BLOCK`, enabling per-policy default-deny within a single tenant.
- Replace the `set_blocklist` agent command with `set_application_control`, carrying
  `{policy_id, policy_version, rules: [{rule_type, identifier, action, enforcement, custom_msg, custom_url}]}`.
- ESF `AUTH_EXEC` handler builds a five-tuple `(cdhash, file_sha256, signing_id_prefixed, leaf_cert_sha256,
  team_id)` per target. `cdhash`, `signing_id`, and `team_id` are read from `es_process_t`; `file_sha256` is
  computed lazily and cached by `(inode, mtime)`; `leaf_cert_sha256` is fetched lazily via
  `SecCodeCopySigningInformation` and cached by `(inode, mtime)`. AUTH callback never blocks on signing-info
  fetch; an as-yet-uncached identifier silently misses for that exec and fills the cache for the next one.
- Add the **block detection event**: when the engine denies an exec, the extension emits an event of kind
  `application_control_block` carrying the matched rule's `(policy_id, rule_id, rule_type, identifier, severity,
  custom_msg)` and the standard process + ancestry metadata. The server's detection-rules engine maps that event
  to an alert with `source='application_control'`, joining the same pipeline as the catalog rules.
- Add the REST surface under `/api/v1/app-control/`:
  - Policies: `GET /policies`, `POST /policies`, `GET /policies/{id}`, `PATCH /policies/{id}`,
    `DELETE /policies/{id}`.
  - Rules: `POST /policies/{id}/rules`, `PATCH /rules/{id}`, `DELETE /rules/{id}`,
    `POST /policies/{id}/rules:bulkUpsert`, `GET /rules` (cross-policy filterable list).
  - Host groups: `GET /host-groups`, `POST /host-groups`, `PATCH /host-groups/{id}`, `DELETE /host-groups/{id}`.
  - Assignments: `POST /policies/{id}/assignments`.
- Add the UI: top-level Application Control nav, policies list, policy detail with rules table, add-rule modal
  with shape-based identifier inference for paste, audit-history view per rule. The `Default` policy is
  auto-created and visible from first boot.
- Operators authenticate to the new endpoints with the existing session cookie + CSRF token. Agents continue to
  authenticate to the command channel with the existing per-host bearer token. No change to enrollment or to
  the persisted host token.

## Capabilities

### New Capabilities

- `server-application-control`: server-side policies, rules, host groups, assignments, fan-out of the
  `set_application_control` command, validation of rule identifiers per type, audit-event emission per
  rule lifecycle action, and the contract for the `application_control_block` event that the extension emits.
- `extension-application-control`: extension-side decision engine — five-tuple identifier extraction from
  `es_process_t` plus lazy/cached SHA-256 of the file and leaf cert, precedence walk, snapshot persistence,
  AUTH_EXEC verdict emission, and the failsafe carve-outs that prevent the policy from blocking the agent,
  the extension, the host app, or `launchd`.

### Modified Capabilities

- `agent-command-executor`: handle the new `set_application_control` command in place of `set_blocklist`. Old
  command path is removed.
- `server-rest-api`: expose the `/api/v1/app-control/*` surface. Remove the legacy `/api/policy` endpoints.
- `web-ui`: add the Application Control screen and remove the legacy `PolicyEditor` screen.
- `server-detection-rules-engine`: map `application_control_block` events to alerts with
  `source='application_control'`, the matched rule's severity, the matched rule's `custom_msg` as the alert
  summary, and the rule and policy identifiers as alert attributes. Existing alert dedup semantics extend to
  the new alert source on the `(host, rule_id, process)` triple.
- `endpoint-event-collection`: the AUTH_EXEC subscription now consults the decision engine for each target and
  emits a verdict event regardless of whether the exec was blocked, so allow-paths in later phases are equally
  observable. Signature-tuple fields (`cdhash`, `signing_id`, `team_id`, `leaf_cert_sha256`) become part of
  every exec event emitted by the extension.

## Impact

**Code:**

- `server/rules/internal/policy/`: replaced with packages for policies, rules, host groups, assignments,
  decision-event ingest, and audit emission.
- `server/rules/api/`: new public types — `ApplicationControlPolicy`, `ApplicationControlRule`, `RuleType`,
  `Action`, `Enforcement`, `HostGroup`, error sentinels for validation. Old `BlocklistPolicy` and
  `set_blocklist` payload types removed.
- `server/rules/bootstrap/schema.go`: drops the `policies` table; creates `app_control_policies`,
  `app_control_rules`, `host_groups`, `app_control_assignments`; seeds `Default` policy and `all-hosts` group.
- `server/rules/internal/operator/handler.go`: REST handlers rewritten for the new surface.
- `server/detection/internal/rules/`: new alert source `application_control` mapped from the new event kind.
- `agent/commander/commander.go`: new `executeSetApplicationControl` in place of `executeSetBlocklist`.
- `extension/edr/extension/PolicyStore.swift`: replaced with a typed five-map snapshot keyed by
  `(rule_type, identifier)`. Atomic write-tmp-then-rename retained.
- `extension/edr/extension/ESFSubscriber.swift`: target tuple builder and decision call site for `AUTH_EXEC`;
  signature-info fetch path is non-blocking with `(inode, mtime)` cache.
- `schema/events.json`: add `application_control_block` event kind with required fields `policy_id`, `rule_id`,
  `rule_type`, `rule_identifier`, `matched_identifier`, `severity`, `custom_msg` (nullable), `custom_url`
  (nullable), `process` (existing schema), `ancestry` (existing schema).
- `ui/src/components/`: remove `PolicyEditor.tsx`; add `ApplicationControl/` directory containing the policies
  list, policy detail, rules table, add-rule modal, and host-groups view (read-only in Phase A).
- `ui/src/api.ts`: remove `fetchPolicy` / `updatePolicy`; add typed clients for `/api/v1/app-control/*`.

**APIs:**

- New REST surface under `/api/v1/app-control/` (operator session + CSRF). All routes are JSON; bulk-upsert
  is idempotent on `(policy_id, rule_type, identifier)`.
- Removed: `GET /api/policy`, `PUT /api/policy`.

**Agent protocol:**

- `set_blocklist` removed. `set_application_control` added. Same command-poll cadence and authentication.

**Events schema:**

- New event kind `application_control_block`. Existing exec event schema extended with `cdhash` and
  `leaf_cert_sha256` fields (optional on existing kinds, required on the new kind).

**Dependencies:**

- No new third-party Go or Swift dependencies. `SecCodeCopySigningInformation` is in the macOS Security
  framework already linked by the extension.

**Cross-context:**

- `rules` context owns the new tables and the REST handlers. `detection` context reads the new event kind
  through the existing event channel. `endpoint` context's command channel carries the new command. No new
  cross-context FK relationships; ADR-0004 boundaries unchanged.

**Rollback:**

- Agent protocol: this change replaces the only command type in `set_blocklist` with `set_application_control`.
  Pre-release; rollback means reverting the entire change set. There is no compatibility shim and none is
  added — that is the intentional cost of operating without released customers.
- Events schema: rolling back the change reverts `schema/events.json` to its prior shape and removes the
  `application_control_block` kind plus the new optional exec-event fields. Server ingestion is tolerant of
  unknown fields, so a partial revert leaves the server able to accept old-shape events without code change.
- Persisted host token: not touched.
- Database: tables introduced in this change are dropped on rollback; the `policies` table is re-created from
  its pre-change schema. The `seed/db.sql` and bootstrap migrations are versioned, so rollback is a matter of
  pointing at the prior bootstrap revision.
