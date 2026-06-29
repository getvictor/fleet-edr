# Design: admin pre-provisioning of users (#509)

## Context

Wave 1 shipped OIDC JIT (every new user lands in `analyst`) and break-glass. Wave 2 (#135) shipped the audited admin surface that lists existing operators and mutates their role bindings and account status, explicitly scoping out an invite flow. This change adds the third onboarding path the issue calls for: an admin stages an email plus role before that person has ever signed in, and the operator lands in the staged role on first SSO login. It reuses the same admin-settings shell, chokepoint, audit recorder, and `role_bindings` model the prior waves built. The `user.invite` action constant, registered and granted to `admin` since wave 1 as a placeholder, finally gets a handler.

## Decisions

### Explicit `provisioned` lifecycle state, not an inferred one

A pre-provisioned account is a `users` row with an email and a role binding but no credential and no `identities` row. Two representations were considered.

The rejected alternative is to infer "pending" from the absence of an `identities` row (no migration). It fails on a real correctness case: identities are CASCADE-deleted with their user, and the sessions schema documents identity rows being deleted on "SSO subject rebind, break-glass credential rotation". An already-active OIDC user whose identity is rebound would transiently have zero identity rows and would be misreported as "pending", and any login logic keyed on the inferred state would misbehave.

The chosen model adds `provisioned` to the `users.status` ENUM. This matches the IAM-industry lifecycle (Okta `STAGED` to `PROVISIONED` to `ACTIVE`, Entra, AWS IAM Identity Center): the staged-but-never-authenticated state is first-class, queryable, and auditable. The list endpoint already serializes `status`, so the UI distinguishes a pending row from its status alone with no extra join. The migration is additive (a wider ENUM); existing rows are untouched.

`LoadActor` already locks out only `disabled`. A `provisioned` user has no session or identity, so it never reaches `LoadActor` before first login, and the reconcile flips it to `active` inside the same transaction that mints the identity. No `LoadActor` change is needed; the deny-by-default direction (anything not `active` cannot act) is preserved because a provisioned user simply has no way to authenticate yet.

### Create endpoint under the existing settings boundary

The route is `POST /api/settings/users`, consistent with the `GET` / `PUT` routes #135 mounted on the same `useradmin.Handler`, so it rides the same operator-session plus CSRF wrapper and the auto-derived allowlist (#463). It funnels through the chokepoint on `user.invite` (listing uses `user.read`, mutation of existing users uses `user.manage`; creation is its own verb, already granted to `admin`).

Body is `{"email": "...", "role": "<bindable role>"}`. Validation mirrors `handleSetRole`: the role must be one of the seeded bindable roles (`analyst`, `senior_analyst`, `auditor`, `admin`); `super_admin` is accepted only when the actor is itself `super_admin` and the UI never offers it; any other value is `invalid_role`. The email is normalized (lowercase, trimmed) and a duplicate returns `409 email_exists` (the `uk_users_email` unique key is the race-safe enforcement point).

### Atomic create lives in the rbac store

`rbac.ProvisionUser(ctx, email, roleID)` opens one transaction, inserts the `users` row with `status='provisioned'` and a NULL credential, inserts one global `role_bindings` row, commits, and returns the new id. The rbac store is already the user-plus-role write surface: `SetUserStatus` issues `UPDATE users SET status` and `SetUserRole` reads users and replaces bindings, both from this store. Adding a create that writes both tables in one transaction is consistent with that ownership and keeps the handler free of transaction management, mirroring how the OIDC provisioner threads a single `*sqlx.Tx` through `users` plus `identities` plus `rbac`. A duplicate email surfaces as a typed sentinel (`api.ErrEmailExists`) the handler maps to 409.

The last-admin guard does not apply: pre-provisioning only ever adds a binding to a brand-new row, so it can never reduce the active-admin count. Pre-assigning a user to `admin` is allowed and harmless because the account cannot act until its first login.

### First-login reconciliation in the OIDC provisioner

`ProvisionOrFind` gains a branch before the `allow_jit` gate. When the OIDC subject has no identity yet and the claim carries a verified email that already belongs to a non-break-glass user with zero identity rows (the pre-provisioned stub), the provisioner adopts that row: it inserts the OIDC identity linking subject to the existing user, flips `status` from `provisioned` to `active`, and keeps the pre-assigned binding rather than binding `DefaultJITRole`. The adoption runs in one transaction with the same duplicate-key race handling as `jitProvision` (a concurrent same-subject callback loses the unique `(provider, subject)` insert and re-resolves).

Adoption is independent of `allow_jit`: a staged account is an explicit admin decision, so binding an identity to it is always honored. `allow_jit` still gates only the creation of a brand-new account for an unknown email. An existing email that belongs to a real account (any identity already present, or break-glass) still returns `ErrEmailConflict`, preserving the wave-1 guard against silently merging identities.

Matching is on the verified email claim only (`Claims.Email` non-empty and `EmailTrusted()`); an unverified email falls through to the synthetic `oidc:<subject>` path and never reconciles, so an attacker cannot claim a staged email without the IdP verifying it.

### Audit

Pre-provisioning emits one `user.provisioned` row through the existing synchronous recorder: actor is the acting admin, target is the new user, payload carries `{"role": "<role>"}`. A dedicated verb (rather than `authz.role_binding.create` plus a `source` payload marker) keeps SIEM correlation keyed on a stable event type and reads cleanly in retention as "an admin staged this user". It is distinct from OIDC JIT creation (`user.created`, payload source `oidc.jit`) and from admin role edits on existing users (`authz.role_binding.*`).

First-login adoption does not emit a new audit verb: the standard `auth.login.success` row plus the original `user.provisioned` row already tell the story (who was staged, into what role, and when they first signed in). Adding an adoption-specific verb would grow the stable action contract for no reviewer-facing gain.

## Risks / trade-offs

- The additive ENUM widening is a schema migration on the identity context. It is non-breaking (existing rows keep their value) and rolls back by leaving the wider ENUM in place, matching the additive-only migration pattern the identity context already follows.
- A pre-provisioned `admin` row sits with elevated intent before anyone signs in. This is acceptable: the row cannot authenticate (no credential, no identity) until its verified-email owner completes SSO, and the `user.provisioned` audit row records the staging the moment it happens.
- Reconciliation adds one `GetByEmail` plus one identity-existence check on the JIT miss path (first login only, not the steady-state identity-found path). Negligible: it runs once per operator, ever.

## Out of scope

OIDC group-to-role mapping (#136), email or invite-link delivery, local-password account creation, host-group or host scope assignment (#137), and a revoke-staged-invite endpoint. All converge additively on the same `users` and `role_bindings` tables.
