# 0017. Unified principal model: one typed actor identity for users and service accounts

- Status: Proposed
- Date: 2026-06-28
- Deciders: getvictor

## Context

The server has two kinds of authenticated actor: human operators (a `users` row, authenticated through an `identities` row of provider `oidc` or `local_password`) and non-human service accounts (a `service_accounts` row, authenticated by a bearer token, ADR-0013). The authorization model treats them as one (both resolve to an `api.Actor` evaluated by the same chokepoint), but the _identity_ model does not. The actor a request carries is `Actor{ UserID int64, ... }`: a human stamps its user id, a service account carries `UserID = 0` and nothing else. Once authentication finishes, which service account is acting is gone.

That gap surfaces as two filed bugs:

- **#514**: a service-account mutation produces an audit row that names nobody (`actor_email="" edr.user.id=0`), and the per-row attribution columns (`oidc_config.updated_by`, `app_config.updated_by`) are `BIGINT` foreign keys to `users(id)`, so a service-account write either violates the FK or, with the interim stopgap, records `NULL`. Either way the acting principal is lost.
- **#518**: service-account detection-config and app-control writes are rejected at the store layer with `actor is required`, because `actorIdentifier()` returns the empty string when `UserID == 0`. An admin-roled service account passes authorization and then fails on an actor-shape assumption.

The attribution surface is also inconsistent across bounded contexts (ADR-0004). The identity and observability contexts attribute with a `BIGINT` FK to `users(id)` (`oidc_config`, `app_config`, `service_accounts.created_by`, `trace_sampler_settings.updated_by`). The rules context attributes with a free-form `VARCHAR` carrying a `"user:<id>"` string (`detection_exclusions`, `detection_rule_settings`, `app_control_*`), defaulting to the literal `"system"`. The detection context stores a `BIGINT` `alerts.updated_by` with no FK. Three representations of the same concept, none of which can name a service account, and a cross-context closure (`UserEmailByID`) exists only to turn `"user:<id>"` back into a display email at read time.

ADR-0013 already named the target vocabulary ("a service account is an `identities` row ... bound to a principal and a role") but the implementation shipped a parallel `service_accounts` table and a user-only actor, so the principal was never built. The audit-log and authentication specs likewise speak of separating "a user (the person) from the identity bindings," but attribution never followed.

Research into current practice for mixed human and non-human identity converges on one pattern: every actor is a _principal_ with a stable, type-tagged, non-reusable identifier, and the audit record is type-aware and never anonymous. Google Cloud IAM identifies members as typed strings (`user:...`, `serviceAccount:...`) backed by an immutable `uniqueId`. AWS CloudTrail records every event's `userIdentity` as `{type, principalId, ...}` with a unique id that is never reused. OIDC carries a `sub` plus subject typing. SPIFFE gives workloads a URI identity. The Cloud Security Alliance's Non-Human Identity work and NIST's Non-Person-Entity guidance both insist machine identities get the same attribution rigor as humans, with a clear type discriminator. ADR-0013's own research reached the same place for the credential model; this ADR extends it to the identity and attribution model.

Three local forces shape the solution:

- **Bounded contexts cap referential integrity (ADR-0004).** The rules context cannot place a foreign key onto an identity-context table. So a single shared-integer principals PK that every attribution column FKs into is not achievable; cross-context attribution must travel as a portable value, not a join.
- **The server is stateless and multi-replica (ADR-0010, ADR-0011).** Whatever identifies a principal must be derivable on any replica without shared in-process state.
- **The product is pre-release (`v0.4.0`).** There is no production attribution history to preserve, so a hard cutover is available: we can rewrite the columns and conventions in one step rather than carrying a compatibility layer.

## Decision

Introduce a first-class **principal** as the single identity every authenticated actor resolves to, and make attribution and audit reference the principal rather than the user.

- **One spine table.** The identity context owns a `principals` table. Every actor (a human user, a service account, and the deployment itself) has exactly one principals row carrying a stable id, a `type`, a display label, and a soft-delete tombstone. `users` and `service_accounts` each gain a `principal_id` that references it.
- **One string identifier, everywhere.** A principal id is a type-prefixed string (`usr_...`, `svc_...`, and the singleton `sys`). It is the `principals` primary key, the value every attribution column stores, the actor id on every audit row, and the id on `api.Actor`. The `type` is both encoded in the prefix (self-describing on the wire and in the database) and stored as a column (the authoritative, indexable discriminator). The local part is the owning row's stable autoincrement key (`usr_<users.id>`, `svc_<service_accounts.id>`), never reused because a removed subtype row leaves a tombstoned `principals` row behind. Within the identity context, attribution columns are real foreign keys to `principals(id)`; across context boundaries the same string is stored without a foreign key (ADR-0004), resolved for display through a single principal resolver.
- **The actor carries the principal.** `api.Actor` replaces `UserID int64` with `Principal PrincipalRef{ ID, Type, Label }`. Session middleware builds it for a human; the service-account authenticator builds it from the token subject, so the acting principal survives authentication. A typed accessor yields the numeric user id for the few genuinely user-on-user operations (self-edit, creator checks).
- **Audit always names a principal.** `audit_events` records `actor_type`, `actor_principal_id`, and a snapshot `actor_label` (the principal's display name at the moment of the action, so renames and deletions never rewrite history). The user-only `actor_user_id` and `actor_email` columns and the read-time `LEFT JOIN users` are removed. The only row that may carry a null principal id is a pre-authentication auth-failure, which records the attempted identifier in the label.
- **Hard cutover, no expand/contract.** A single set of forward-only goose migrations (ADR-0009) rewrites every attribution column to the principal id, backfills existing dev and QA rows, and drops the legacy columns. The application code moves straight to the principal model: no dual-write, no compatibility shim, no interim `NULL`. The `"user:<id>"`, `"system"`, and `updated_by = NULL` conventions are removed, and the interim #515 SSO stopgap is deleted.

The change is scoped to identity and attribution. It deliberately does **not** touch the authorization hot path: service accounts keep their single `role_id` column and the authenticator keeps synthesizing one global binding, so the OPA input shape is unchanged.

## Consequences

- **Easier**:
  - #514 and #518 close structurally, not by special-casing: every actor has a non-empty principal id, so the `actor is required` gate and the FK violation cannot recur.
  - One attribution representation replaces three. The `"user:<id>"` / `"system"` / `BIGINT`-FK split collapses to one string, and the type-specific email-resolver closures (`UserEmailByID`, the detection-config `userEmailResolver`, `parseUserActorID`) are replaced by a single principal resolver, or removed where audit now snapshots the label.
  - Audit rows are self-contained: a principal id plus a snapshot label, with no join to a mutable table, which also means a deleted user's history stays attributable.
  - New actor types (a future `agent` principal for endpoint-initiated actions, a federated identity) are additive: add a `type` and a subtype table; no attribution column changes again.
- **Harder / the cost**:
  - This is a wide one-time migration that touches every bounded context's attribution columns and the audit schema. It is a hard cutover, so a rollback to the prior binary cannot read the new attribution columns; this is acceptable pre-release and is the explicit product choice.
  - `principals.id` is a `VARCHAR` primary key rather than a packed `BINARY(16)`. The table is tiny (operators plus service accounts plus one system row), so the index-size and join-cost difference is irrelevant, but it is a deliberate trade of micro-efficiency for one uniform representation across the context boundary.
  - The snapshot label on audit rows is point-in-time by design; a live config view (for example the exclusions list) that wants the _current_ label must resolve it through the principal resolver rather than read it off the row.
  - The identity context now publishes a principal concept that other contexts depend on as a string value. A reviewer must reject any new attribution column that stores a bare user id or invents a fourth convention.
  - This does not reconcile the ADR-0013 divergence (service accounts as a separate table rather than `api_token` identities) nor unify `role_bindings` across principal types. Both become cleaner once the spine exists and are recorded below as the convergence target, not done here.

## Alternatives considered

**Typed string only, no spine table.** Store `"<type>:<id>"` in every column and on the actor, with no `principals` table. The cheapest option and the one first sketched in discussion. Rejected: there is no referential integrity and no single place to ask "does this principal exist, is it disabled, what is its label." The type lives only inside a fragile parsed string, and every consumer re-implements the parse. A spine table gives one existence check and one label source for the cost of one small table.

**Polymorphic `(actor_type, actor_id)` column pair everywhere.** Carry two columns on every attribution row and on the actor. Rejected: it duplicates the discriminator across dozens of columns, keeps two fields in sync by convention, and still offers no single existence check. One self-describing string is simpler to store, index by prefix, and reason about.

**Shared-integer principals PK with cross-context foreign keys.** A `BIGINT` `principals.id` that every attribution column references. Rejected: ADR-0004 forbids a foreign key from the rules or detection context into an identity-context table, so the integrity this buys exists only inside identity anyway, while forcing a join everywhere. The string id gives intra-context FKs where they are possible and a portable value where they are not.

**`BINARY(16)` UUIDv7 PK with a string projection.** Store a packed UUID as the key and project a `"<type>:<uuid>"` string for the wire and for cross-context columns. Rejected: it reintroduces exactly the binary-here, string-there duality this change is trying to remove. A `VARCHAR` everywhere is one representation, and the table is too small for the packed-key win to matter.

**Reconcile to `api_token` identities and unify `role_bindings` now (the ADR-0013 shape).** Make a service account an `identities` row under a user-less principal, and move its single role into `role_bindings` so one binding path serves all principals. Attractive as the truly unified end state. Rejected for this change: it reworks the authorization hot path and the OPA input shape, which is a separate, riskier concern. The principal spine makes it a clean follow-up; doing it here would make a wide attribution change also a hot-path change.

**Expand/contract migration.** Add the principal columns, dual-write both representations, migrate reads, then drop the legacy columns over several releases. The standard zero-downtime path. Rejected by product: the deployment is pre-release with no attribution history worth preserving, so the compatibility layer is pure cost. A hard cutover leaves no `"user:<id>"`-versus-principal duality for future code to navigate, which is the point.

## References

- Issue #514 (service-account actions are unattributable) and #518 (service accounts cannot write detection-config: actor required at store layer), the two bugs this change closes
- Issue #376 and ADR-0013 ([`0013-service-account-and-api-authentication.md`](0013-service-account-and-api-authentication.md)): the service-account credential model whose identity side this completes (the unbuilt "bound to a principal" language)
- ADR-0004 ([`0004-modular-monolith-bounded-contexts.md`](0004-modular-monolith-bounded-contexts.md)): the context boundary that caps cross-context foreign keys and forces the portable-string attribution
- ADR-0009 ([`0009-migrations-via-goose.md`](0009-migrations-via-goose.md)): the forward-only migration mechanism the hard cutover uses
- ADR-0010 ([`0010-stateless-server.md`](0010-stateless-server.md)): the stateless topology the replica-independent principal id serves
- Prior art: Google Cloud IAM member identifiers + `uniqueId`; AWS CloudTrail `userIdentity` (`type` + `principalId` + `sessionContext`); OIDC `sub` and subject typing; SPIFFE workload identity; the Cloud Security Alliance Non-Human Identity model; NIST SP 800-207 / 800-63 Non-Person-Entity guidance
- `openspec/changes/unified-principal-model/`: the change proposal implementing this decision
