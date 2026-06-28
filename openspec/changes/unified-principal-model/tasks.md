# Tasks

## Identity API: the principal boundary

- [ ] Add `PrincipalType` + `PrincipalRef{ID, Type, Label}` to `server/identity/api` with a `UserID() (int64, bool)` accessor (valid only for `usr_` ids) and a mint helper that sets prefix + type together.
- [ ] PBT: `PrincipalRef` id round-trips mint -> parse for every type; `UserID()` is true only for `usr_`.
- [ ] Replace `Actor.UserID int64` with `Actor.Principal PrincipalRef` in `authz.go`; update `WithActor`/`ActorFromContext` doc comments.
- [ ] Replace `AuditEvent.UserID *int64` + `ActorEmail string` with `AuditEvent.Actor PrincipalRef`; update `AuditRow` to carry `actor_type`/`actor_principal_id`/`actor_label`.

## Identity schema (migration 00005)

- [ ] Create `principals` (id, type ENUM, display_label, disabled_at, created_at; index on type) and seed the `sys` row.
- [ ] Add `principal_id VARCHAR(40)` (unique, FK to principals) to `users` and `service_accounts`; backfill `usr_<id>` / `svc_<id>` and the labels.
- [ ] Rewrite `oidc_config.updated_by`, `app_config.updated_by`, `service_accounts.created_by` from `BIGINT REFERENCES users(id)` to `VARCHAR(40) REFERENCES principals(id)`; backfill `usr_<id>`, default new system writes to `sys`.
- [ ] Rewrite `audit_events`: add `actor_type`/`actor_principal_id`/`actor_label`, backfill from `actor_user_id`/`actor_email`, drop the two legacy columns, swap the actor index.

## Identity code

- [ ] `service.LoadActor`: build `PrincipalRef` (user) from the user row.
- [ ] `serviceaccounts/authenticator.go`: build `PrincipalRef` (service_account) from the token subject -> SA principal id + name. This is the root fix for #514/#518.
- [ ] `audit/mysql.go`: write the three principal columns; drop the `LEFT JOIN users` in `List`; read the snapshot label; remove `resolveActorEmail`.
- [ ] Update every `AuditEvent` construction in identity (`useradmin`, `breakglass`, `oidc`, `saadmin`, `authz/engine`, `login`, `ssoadmin`) to set `Actor PrincipalRef`; login-failure rows set a null-id ref with the attempted email as label.
- [ ] `useradmin`/`saadmin` user-on-user checks use `Principal.UserID()`.
- [ ] Delete the #515 SSO stopgap: remove the nullable `*int64` threading in `ssoadmin/handler.go` and the `bootstrap.go` apply closure; the SSO + app-config update stamps `Principal.ID`.
- [ ] `ssoconfig`/`appconfig` stores: `updated_by` becomes the principal id string (default `sys` on env-seed).
- [ ] Add the principal-label resolver to `identity/api` (resolves any principal type); retire `Service.GetUser`-only email lookups where they served attribution.

## Observability (migration 00002 + code)

- [ ] Rewrite `trace_sampler_settings.updated_by` `BIGINT` -> `VARCHAR(40)`; backfill `usr_<id>`.
- [ ] `tracingadmin`/`tracingconfig`: stamp `Principal.ID`; audit sets `Actor`.

## Rules (migration 00003 + code)

- [ ] Rewrite values in `detection_exclusions`, `detection_rule_settings`, `app_control_policies`, `app_control_rules` attribution columns: `"user:<id>" -> usr_<id>`, `"system" -> sys`; change column default to `'sys'`.
- [ ] `detectionconfig/store.go` + `appcontrol/store.go`/`service.go`: the `actor is required` gates accept any non-empty principal id; a service-account write satisfies them (closes #518).
- [ ] Delete `actorIdentifier` / `actorIdentifierFromContext` / `parseUserActorID`; stamp `Principal.ID` directly; audit sets `Actor`.
- [ ] Replace the detection-config `userEmailResolver` / `SetUserEmailResolver` / `resolveCreatedByEmails` with the identity principal-label resolver; the `created_by_email`-style field is filled for service accounts too.
- [ ] `rules/bootstrap`: drop the `UserEmailByID` dep in favor of the principal resolver.

## Detection (migration 00008 + code)

- [ ] Rewrite `alerts.updated_by` `BIGINT` -> `VARCHAR(40)`; backfill `usr_<id>`.
- [ ] `detection/internal/mysql/alerts.go` + `operator/handler.go` + `service/service.go`: stamp/read `Principal.ID`; the `UserExists` FK-replacement check becomes a principal existence check; audit sets `Actor`.

## cmd/main wiring

- [ ] Remove `userEmailByIDFromIdentity`; wire the single principal-label resolver into the rules + detection bootstraps.

## Cross-cutting tests

- [ ] #518 regression: table over every authed write route exercised with a service-account actor; assert no `actor is required` rejection and an audit row + per-row attribution of `svc_<id>`.
- [ ] Integration: SA SSO update, SA detection-config exclusion create, SA app-control rule create each record `svc_<id>` in the audit row and the attribution column.
- [ ] Audit reader: a deleted user's history resolves the snapshot label with no join.
- [ ] Spectrace markers reference the new/modified scenario IDs in the delta specs.

## Docs

- [ ] ADR-0017 (done in this change) and the openspec delta; note the deferred items (api_token reconciliation, role_bindings unification, delegation, agent principal).
