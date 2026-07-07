# Unified principal model

## Why

A service-account action is unattributable. The authenticated actor carries only a user id (`api.Actor.UserID int64`); a service account authenticates with `UserID = 0` and nothing else, so once authentication finishes the acting service account is gone. This breaks attribution two ways:

- **#514**: a service-account mutation writes an audit row that names nobody (`actor_email="" edr.user.id=0`), and the per-row attribution columns (`oidc_config.updated_by`, `app_config.updated_by`) are `BIGINT` foreign keys to `users(id)`, so a service-account write either violates the FK or, with the interim #515 stopgap, records `NULL`.
- **#518**: a service-account detection-config or app-control write passes authorization and is then rejected at the store layer with `actor is required`, because `actorIdentifier()` returns `""` when `UserID == 0`.

Attribution is also represented three different ways across bounded contexts: a `BIGINT` FK to `users(id)` (identity, observability), a `VARCHAR` `"user:<id>"` / `"system"` string (rules), and an unconstrained `BIGINT` (detection `alerts.updated_by`). None can name a service account.

ADR-0017 records the decision: a first-class, typed principal that every authenticated actor resolves to. This proposal implements it as a hard cutover (no expand/contract): the product is pre-release, so there is no attribution history to preserve.

## What Changes

- **A `principals` spine.** The identity context gains a `principals` table. Every actor (a human user, a service account, and the deployment itself) has one row with a stable type-prefixed string id (`usr_...`, `svc_...`, the singleton `sys`), a `type`, a display label, and a soft-delete tombstone. `users` and `service_accounts` each reference it.
- **One string identifier everywhere.** The principal id is the value every attribution column stores, the actor id on every audit row, and the id on `api.Actor`. Within identity it is a real FK to `principals(id)`; across contexts it is the same string with no FK (ADR-0004).
- **The actor carries the principal.** `api.Actor` replaces `UserID int64` with `Principal PrincipalRef{ ID, Type, Label }`. The service-account authenticator populates it from the token subject. A typed accessor yields the numeric user id for the few user-on-user operations (self-edit, creator checks).
- **Audit always names a principal.** `audit_events` records `actor_type`, `actor_principal_id`, and a snapshot `actor_label`; the user-only `actor_user_id` and `actor_email` columns and the read-time `LEFT JOIN users` are removed. A pre-authentication auth-failure is the only row that may carry a null principal id, recording the attempted identifier in the label.
- **Service accounts can perform every write their role permits.** The `actor is required` store gates accept any principal id; a service-account-initiated mutation records `svc_<id>` and is attributable through the audit API alongside user actions. This closes #518 across detection-config and app-control.
- **BREAKING (operational, one-time): hard switch with no compatibility layer.** Forward-only migrations rewrite every attribution column to the principal id, backfill existing dev and QA rows, and drop the legacy columns. The `"user:<id>"`, `"system"`, and `updated_by = NULL` conventions and the interim #515 SSO stopgap are removed. A rollback to the prior binary cannot read the new columns; acceptable pre-release.
- **Unchanged:** the authorization hot path. Service accounts keep their single `role_id` column and the authenticator keeps synthesizing one global binding, so the OPA input shape does not change.

## Capabilities

### New Capabilities

<!-- None. The principal is owned by the existing identity capabilities; this change reshapes how they identify an actor. -->

### Modified Capabilities

- `server-identity-authorization`: the actor the chokepoint evaluates carries a typed principal, not a bare user id.
- `server-identity-audit-log`: every audit row names a typed principal with a snapshot label; the user-only columns are removed.
- `server-identity-service-accounts`: a service account is a principal; its mutations are attributable and never rejected for actor shape.
- `server-application-control`: per-row attribution references the principal; a service account can write.
- `server-detection-rules-engine`: detection-config per-row attribution references the principal; a service account can write.
- `sso-configuration`: per-row attribution references the principal; the interim service-account `NULL` behavior is removed.

## Impact

- **Affected specs:** `server-identity-authorization` (1 added), `server-identity-audit-log` (2 modified), `server-identity-service-accounts` (1 added, 1 modified), `server-application-control` (1 modified), `server-detection-rules-engine` (1 modified), `sso-configuration` (1 modified).
- **Affected code:** `server/identity/api` (`Actor`, new `PrincipalRef` + `AuditEvent` principal fields); the service-account authenticator and session middleware (actor construction); the audit store (`audit_events` columns, read query); every attribution write across identity (`oidc_config`, `app_config`, `service_accounts`), observability (`trace_sampler_settings`), rules (`detection_exclusions`, `detection_rule_settings`, `app_control_*`), and detection (`alerts.updated_by`); the store-layer actor gates (detection-config, app-control); the cross-context email-resolver closures (`UserEmailByID`, detection-config `userEmailResolver`, `parseUserActorID`), replaced by a single principal resolver or removed where audit snapshots the label; the interim #515 ssoadmin/bootstrap stopgap. New migrations in identity, observability, rules, and detection.
- **Migrations:** identity `00005`, observability `00002`, rules `00003`, detection `00008` (next available per context). Each creates or rewrites attribution columns and backfills (`user id -> usr_<id>`, `"user:<id>" -> usr_<id>`, `"system" -> sys`).
- **Preserved invariants:** ADR-0004 (no cross-context FK; attribution travels as a string), ADR-0009 (forward-only goose), ADR-0010 (replica-independent id), and the authorization chokepoint contract and OPA input shape.
- **Deferred (design-compatible, ADR-0017):** reconciling service accounts to `api_token` identities, unifying `role_bindings` across principal types, a delegation `on_behalf_of_principal_id`, and a future `agent` principal type. None are built here; the spine makes each additive.
