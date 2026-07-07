## 1. Schema + audit action

- [ ] 1.1 Add migration `server/identity/migrations/00007_user_provisioned_status.sql`: widen `users.status` ENUM to `('active','disabled','provisioned')`, default unchanged
- [ ] 1.2 Add `AuditUserProvisioned = "user.provisioned"` to `server/identity/api/audit.go`

## 2. Store methods

- [ ] 2.1 `rbac.Store`: `ProvisionUser(ctx, email, roleID)` returns the new user id; one transaction inserts the `users` row (`status='provisioned'`, NULL credential) and one global `role_bindings` row; duplicate email surfaces as `api.ErrEmailExists`
- [ ] 2.2 `users.Store`: `Activate(ctx, ec, userID)` flips `status` from `provisioned` to `active` under a caller tx
- [ ] 2.3 `identities.Store`: `HasAnyForUser(ctx, userID)` reports whether the user has any identity row
- [ ] 2.4 Unit tests for the new store methods (provision create + dup-email, activate transition, has-any)

## 3. Create handler + wiring

- [ ] 3.1 Add `handleCreate` to `server/identity/internal/useradmin/handler.go`: `POST /api/settings/users` gated on `user.invite`; validate email + role (reuse `bindableRoles`; super_admin only for super_admin actor); map dup-email to `409 email_exists`
- [ ] 3.2 Emit the `user.provisioned` audit row on success with payload `{role}`
- [ ] 3.3 Register the route in `RegisterAuthedRoutes`; extend the handler's `RolesStore` interface with `ProvisionUser`
- [ ] 3.4 Construct the handler with the rbac store reference in `server/identity/bootstrap/bootstrap.go`

## 4. First-login reconciliation

- [ ] 4.1 In `oidc.ProvisionOrFind`: before the `allow_jit` gate, when identity is missing and the verified email matches a non-break-glass user with no identities, adopt it (link identity, `Activate`, keep pre-assigned role) regardless of `allow_jit`
- [ ] 4.2 Preserve `ErrEmailConflict` for an email already bound to an account with any identity (or break-glass); keep the duplicate-key race re-resolve
- [ ] 4.3 Unit + integration tests: adoption keeps role, flips status, works with JIT off; conflict path unchanged

## 5. Backend tests + spectrace markers

- [ ] 5.1 Integration tests in `server/identity/internal/tests` for create (success + audit), invite-grant deny, super_admin reject, duplicate email, and first-login adoption
- [ ] 5.2 Add `spec:` markers tying tests to the `server-identity-authorization` scenarios in this change's delta

## 6. UI

- [ ] 6.1 `ui/src/permissions-core.ts`: add `UserInvite` constant
- [ ] 6.2 `ui/src/api.ts`: `createUser(email, role)` helper (CSRF on mutation)
- [ ] 6.3 `ui/src/components/Users/Users.tsx` + `.scss`: add-user form gated on `UserInvite`, pending badge for status `provisioned`, refresh on success
- [ ] 6.4 Vitest: add-user flow, control hidden without grant, pending badge; add the `web-ui` spectrace marker

## 7. Docs + traceability + gates

- [ ] 7.1 Update `docs/authz.md` to document the pre-provisioning path alongside the SQL break-glass alternative
- [ ] 7.2 `openspec validate add-user-preprovisioning --strict`; `go run ./tools/spectrace check --strict`
- [ ] 7.3 `go test ./server/...`, `task lint:go`, `task lint:dashes`, `cd ui && npm test`
- [ ] 7.4 Manual QA on the dev server (Chrome MCP): pre-provision a user, confirm the pending row + the `user.provisioned` audit row, simulate first login landing in the pre-assigned role
