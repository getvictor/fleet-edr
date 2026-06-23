## 1. Authorization action + audit + policy bundle

- [x] 1.1 Add `ActionUserManage = "user.manage"` to `server/identity/api/authz.go` and include it in `RegisteredActions()`
- [x] 1.2 Mirror `user.manage` into `policy/data/actions.json` and grant it to `admin` in `policy/data/roles.json`; keep `TestPolicy_ActionsParity` green
- [x] 1.3 Add audit action constants in `server/identity/api/audit.go`: `authz.role_binding.create`, `authz.role_binding.update`, `authz.role_binding.delete`, `user.disabled`, `user.enabled`

## 2. Store methods

- [x] 2.1 `users.Store`: `List(ctx)` returning an admin view (id, email, display_name, status, is_breakglass, created_at); `SetStatus(ctx, id, status)`
- [x] 2.2 `rbac.Store`: `AllLiveBindings(ctx)` (map user id to live global role ids); `SetUserRole(ctx, userID, roleID)` (transactional replace of global bindings, returns previous role ids); `CountActiveAdmins(ctx, excludeUserID)` (active users holding an admin-tier role, joined to users.status)
- [x] 2.3 Unit tests for the new store methods (rbac set-role replace + count, users list + status)

## 3. Admin handler + wiring

- [x] 3.1 New `server/identity/internal/useradmin` handler: `GET /api/settings/users`, `PUT /api/settings/users/{id}/role`, `PUT /api/settings/users/{id}/status`, gated on `user.read` / `user.manage`
- [x] 3.2 Enforce guardrails: last-admin, no self-management, break-glass immutable, super_admin restricted; reject with no state change
- [x] 3.3 Emit the audit rows on applied mutations; no-op mutations succeed without auditing
- [x] 3.4 Construct + wire the handler in `server/identity/bootstrap/bootstrap.go` (`RegisterAuthedRoutes`)
- [x] 3.5 Enumerate the three routes in the `server/cmd/fleet-edr-server/main.go` session-protected allowlist

## 4. Backend tests + spectrace markers

- [x] 4.1 Integration tests in `server/identity/internal/tests` for list, set-role (replace + audit), disable (audit), and every guardrail
- [x] 4.2 Add `spec:` markers tying tests to the `server-identity-authorization` scenarios in this change's delta

## 5. UI

- [x] 5.1 `ui/src/permissions-core.ts`: add `UserRead` and `UserManage` constants
- [x] 5.2 `ui/src/api.ts`: `User` type + `listUsers`, `setUserRole`, `setUserStatus` (CSRF on mutation)
- [x] 5.3 `ui/src/components/Users/Users.tsx` + `.scss`: table with inline role selector + enable/disable, gated via `useCan()`
- [x] 5.4 Add the Users item to `SettingsLayout`; add the `/admin/settings/users` route in `App.tsx`
- [x] 5.5 Vitest: `Users.test.tsx` (list + role change + page hidden without grant), api client test, SettingsLayout test; add the `web-ui` spectrace marker

## 6. Docs + traceability + gates

- [x] 6.1 Update `docs/authz.md`: the SQL promotion pattern becomes the documented break-glass alternative, not the primary path
- [x] 6.2 `openspec validate user-role-management --strict`; `go run ./tools/spectrace check --strict`
- [x] 6.3 `go test ./server/...`, `task lint:go`, `task lint:dashes`, `cd ui && npm test`
- [x] 6.4 Manual QA on the dev server (Chrome MCP): promote a user analyst to senior_analyst, disable/enable, confirm the audit rows
