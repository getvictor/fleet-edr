# Tasks

## Identity API: the principal boundary

- [x] Add `PrincipalType` + `PrincipalRef{ID, Type, Label}` to `server/identity/api` with a `UserID() (int64, bool)` accessor (valid only for `usr_` ids) and mint helpers that set prefix + type together.
- [x] PBT: `PrincipalRef` id round-trips mint -> parse for every type; `UserID()` is true only for `usr_`; plus a JSON round-trip property.
- [x] Replace `Actor.UserID int64` with `Actor.Principal PrincipalRef` in `authz.go`.
- [x] Replace `AuditEvent.UserID *int64` + `ActorEmail string` with `AuditEvent.Actor PrincipalRef`; `AuditRow` carries the typed `Actor` (with `UserID`/`UserEmail` derived from it for back-compat).

## Identity schema (migrations 00005 + 00006)

- [x] Create `principals` (id, type ENUM, display_label, disabled_at, created_at; index on type) and seed the `sys` row; backfill one row per user / service account (00005).
- [x] Refinement (vs the original draft): user/service-account principals use a deterministic id (`usr_<users.id>` / `svc_<service_accounts.id>`) created in the same transaction as the row, rather than a stored `principal_id` FK column on `users`/`service_accounts`. Determinism makes the column redundant and sidesteps the insert-ordering chicken-and-egg; attribution columns still FK `principals(id)`.
- [x] Rewrite `oidc_config.updated_by`, `app_config.updated_by`, `service_accounts.created_by` to `VARCHAR(40) REFERENCES principals(id)`; backfill `usr_<id>`, default system writes to `sys` (00006).
- [x] Rewrite `audit_events`: add `actor_type`/`actor_principal_id`/`actor_label`, backfill (legacy `actor_user_id=0` -> no principal), drop the two legacy columns, swap the actor index (00005).

## Identity code

- [x] `service.LoadActor` builds the user `PrincipalRef`; user/SA creation paths insert the principals spine row in one transaction.
- [x] `satoken` claims carry the SA `principal_id` + display name, stamped at the token endpoint; the authenticator builds the `PrincipalRef` from the claims with no DB read (root fix for #514/#518), rejecting a token with no principal claim.
- [x] Replace hardcoded `"system"` / `"user:"+` attribution literals (app-control seed, rules columns) with the `sys` principal id / `Principal.ID` (00003 + store seed).
- [x] `audit/mysql.go` writes the three principal columns, drops the `LEFT JOIN users`, reads the snapshot label; `resolveActorEmail` + the transitional `actorOf` bridge removed.
- [x] Every `AuditEvent` emitter (identity `useradmin`/`breakglass`/`oidc`/`saadmin`/`authz`/`login`/`ssoadmin`/`jit`, plus endpoint/response/rules/detection) sets `Actor`; pre-auth failures set a label-only ref.
- [x] `useradmin` self-edit check uses `Principal.UserID()`.
- [x] Delete the #515 SSO `NULL` stopgap; SSO + app-config update stamps `Principal.ID`.
- [x] `ssoconfig`/`appconfig` stores: `updated_by` is the principal id string (defaults to `sys`).
- [x] A single identity-owned principal-label resolver (`Service.PrincipalLabel`) that resolves any principal type: a user to its email, a service account to its name, the system principal to "system". The detection-config exclusions list now resolves every author through it.

## Observability (migration 00002 + code)

- [x] Rewrite `trace_sampler_settings.updated_by` to `VARCHAR(40)`; tracing-admin store + audit thread `Principal.ID` / set `Actor`.

## Rules (migration 00003 + code)

- [x] Rewrite the `detection_*` + `app_control_*` attribution values (`user:<id>` -> `usr_<id>`, `system` -> `sys`) and change the column defaults to `'sys'`.
- [x] The `actor is required` store gates accept any non-empty principal id; a service-account write satisfies them (closes #518).
- [x] `actorIdentifier` / `actorIdentifierFromContext` return `Principal.ID`; audit emitters set `Actor`.
- [x] The exclusions list exposes `created_by_label` (a user's email or a service account's name), resolved via `Service.PrincipalLabel`. Replaces the user-only `created_by_email`.

## Detection (migration 00008 + code)

- [x] Rewrite `alerts.updated_by` to `VARCHAR(40)`; operator/service/store thread the principal id; audit sets `Actor`.
- [x] Refinement: the `UserExists` FK-replacement check runs only for a user principal (parsed from `usr_<id>`); a service-account/system principal is trusted from the authenticated actor.

## Cross-cutting tests

- [x] `PrincipalRef.UserID()` negative cases; JSON round-trip; mint/parse PBT.
- [x] System-write + deleted-user snapshot tests (audit label survives, no join); direct service-account audit-snapshot.
- [x] #518 regression: a service-account actor over the detection-config write routes asserts no `actor is required` rejection and `svc_<id>` attribution.
- [x] Integration: SA SSO update records `svc_<id>` on both `updated_by` columns; SA detection-config exclusion create records `svc_<id>`.
- [ ] DEFERRED: SA app-control rule create via the full REST harness (covered structurally by the shared `actorIdentifierFromContext` path the route-sweep exercises).

## Docs

- [x] ADR-0017 + the openspec delta (on main); deferred items (api_token reconciliation, role_bindings unification, delegation, agent principal) recorded in the ADR.
