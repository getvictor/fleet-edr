# Design: unified principal model

This is the concrete shape behind ADR-0017. It records the schema, the Go boundary types, the hard-cutover migration plan, and the per-site code changes.

## Principal identifier

A principal id is a type-prefixed string, the primary key of `principals`, and the single value stored everywhere an actor is attributed.

- Prefixes: `usr_` (user), `svc_` (service account), and the singleton `sys` (the deployment itself).
- The local part is the owning subtype row's stable autoincrement key: `usr_<users.id>` and `svc_<service_accounts.id>`. It is never reused, because a deleted user or service account leaves its `principals` row in place (tombstoned via `disabled_at`) and the autoincrement key is never reissued. `PrincipalRef.UserID()` parses `usr_<n>` back to the numeric `users.id` for the user-on-user paths; nothing else parses the local part.
- The `type` is stored as a column too. The prefix is the self-describing wire form; the column is the authoritative, indexable discriminator. The two never disagree (a single mint helper sets both).

## Schema

### Identity: `principals` (new) and references (migration 00005)

```sql
CREATE TABLE principals (
  id            VARCHAR(40)  PRIMARY KEY,            -- usr_... | svc_... | sys
  type          ENUM('user','service_account','system') NOT NULL,
  display_label VARCHAR(255) NOT NULL,               -- resolvable name: user email, SA name, "system"
  disabled_at   TIMESTAMP(6) NULL,                   -- tombstone; attribution survives a deleted subtype row
  created_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  INDEX idx_principals_type (type)
);
```

`users` and `service_accounts` each gain `principal_id VARCHAR(40) NOT NULL` with a unique key and an FK to `principals(id)`. The seeded `sys` principal is inserted by the migration and is the default for system-originated writes (env-seed, background jobs) that previously stored `NULL` or `"system"`.

Attribution columns in the identity context are rewritten from `BIGINT REFERENCES users(id)` to `VARCHAR(40) REFERENCES principals(id)`:

- `oidc_config.updated_by`, `app_config.updated_by`: `VARCHAR(40) NOT NULL DEFAULT 'sys' REFERENCES principals(id)`. Because principals are never hard-deleted (a removed user or service account leaves a tombstoned `principals` row with `disabled_at` set), there is no `ON DELETE SET NULL` and the column is never `NULL`: an env-seed or background write with no operator records `sys`. This removes the #514 `NULL`-attribution case entirely.
- `service_accounts.created_by`: same `VARCHAR(40) REFERENCES principals(id)` (nullable, as today, for the env-seeded first account that has no creating operator).

### Identity: `audit_events` (migration 00005, same file)

Replace the user-only columns with principal columns:

```sql
ALTER TABLE audit_events
  ADD COLUMN actor_type         VARCHAR(32)  NULL AFTER occurred_at,
  ADD COLUMN actor_principal_id VARCHAR(40)  NULL AFTER actor_type,
  ADD COLUMN actor_label        VARCHAR(255) NULL AFTER actor_principal_id;
-- backfill from actor_user_id / actor_email, then:
ALTER TABLE audit_events
  DROP COLUMN actor_user_id,
  DROP COLUMN actor_email;
-- index: idx_audit_events_actor (actor_principal_id, occurred_at)
```

`actor_principal_id` is null only for a pre-authentication auth-failure row, which records the attempted identifier in `actor_label`. `actor_label` is a snapshot: the principal's `display_label` at the moment of the action, so a later rename or deletion does not rewrite history. No `LEFT JOIN users` on read. `actor_type` is a plain `VARCHAR(32)`, not the `principals.type` `ENUM` and not an FK: `audit_events` is deliberately unconstrained (the same posture as the existing nullable, unconstrained `actor_user_id`), so audit history is never invalidated by a deleted principal or a later widening of the type set.

### Observability, rules, detection (migrations 00002 / 00003 / 00008)

- observability `trace_sampler_settings.updated_by`: `BIGINT` to `VARCHAR(40)` (no cross-context FK; store the string). Backfill `usr_<id>`.
- rules `detection_exclusions.created_by`, `detection_rule_settings.updated_by`, `app_control_policies.created_by/updated_by`, `app_control_rules.created_by/updated_by`: already `VARCHAR`; rewrite values `"user:<id>" -> usr_<id>`, `"system" -> sys`. Change the column default from `'system'` to `'sys'`.
- detection `alerts.updated_by`: `BIGINT` (no FK) to `VARCHAR(40)`. Backfill `usr_<id>`.

## Go boundary

`server/identity/api` gains the principal value type and reshapes `Actor` and `AuditEvent`.

```go
type PrincipalType string
const (
    PrincipalUser           PrincipalType = "user"
    PrincipalServiceAccount PrincipalType = "service_account"
    PrincipalSystem         PrincipalType = "system"
)

// PrincipalRef is the portable identity of an actor. ID is the type-prefixed string;
// Type is the discriminator; Label is the display name (email / SA name / "system").
type PrincipalRef struct {
    ID    string        `json:"id"`
    Type  PrincipalType `json:"type"`
    Label string        `json:"label"`
}

// UserID returns the numeric users.id when this principal is a user. Only the
// user-on-user paths (self-edit, creator checks) call it; everything else uses ID.
func (p PrincipalRef) UserID() (int64, bool) { /* parse usr_<n>; false otherwise */ }
```

`Actor.UserID int64` is replaced by `Actor.Principal PrincipalRef`. `AuditEvent.UserID *int64` + `ActorEmail string` are replaced by `AuditEvent.Actor PrincipalRef` (the recorder writes `actor_type`, `actor_principal_id`, `actor_label = Actor.Label`).

Actor construction (callers read the stored `principal_id`, they do not reconstruct it):

- Session middleware / `service.LoadActor`: reads the user row's stored `principal_id` (which is `usr_<users.id>` by construction) into `PrincipalRef{ID: principal_id, Type: user, Label: email}`.
- Service-account authenticator: builds the ref from the access-token claims, with no DB read (the ADR-0013 stateless hot path). The token endpoint, which already reads the service-account row to verify the credential, mints that row's `principal_id` and display name into the token alongside the existing subject/role/epoch claims; the authenticator reads them straight into `PrincipalRef{ID, Type: service_account, Label}`. This is the line that fixes #514 and #518 at the root: the principal survives authentication.

## Principal resolution (replacing the email closures)

Audit rows snapshot the label at write time, so audit reads need no resolver. Live config views (the detection-config exclusions list) that want the *current* label resolve `principal_id -> display_label` through one identity-owned resolver exposed on `identity/api`, replacing the user-only `UserEmailByID` closure and the detection-config `userEmailResolver` / `parseUserActorID`. The resolver handles every principal type, so the UI's `created_by_email`-style field is filled for service accounts too.

## Per-site code changes

Grouped by the enumeration behind ADR-0017. Each is a hard edit to the principal model, no compatibility branch.

1. **`Actor.UserID` reads** become `Actor.Principal` reads. The user-on-user checks (`useradmin/handler.go`, `saadmin/handler.go`) use `Principal.UserID()`. The attribution stamps (`ssoadmin`, `tracingadmin`, `appcontrol/service.go`, `detectionconfig/service.go`, detection `operator/handler.go`) stamp `Principal.ID`.
2. **Actor construction** (`service.LoadActor`, `serviceaccounts/authenticator.go`) builds a `PrincipalRef` from the stored `principal_id`. The service-account token claims (`satoken`) gain the `principal_id` + display name so the stateless authenticator needs no DB read; the token endpoint stamps them at mint time.
3. **`"user:<id>"` build/parse** (`actorIdentifier`, `actorIdentifierFromContext`, `parseUserActorID`) is deleted; the principal id is used directly.
4. **Attribution writes** across all contexts bind `Principal.ID`. The identity columns become principal FKs; the rest store the string.
5. **`actor is required` gates** (`detectionconfig/store.go`, `appcontrol/store.go` + `service.go`) accept any non-empty principal id; a service-account write now satisfies them.
6. **`AuditEvent` constructions** set `Actor PrincipalRef` instead of `UserID`/`ActorEmail`. Login-failure rows set a null-id ref with the attempted email as label.
7. **Audit store** (`audit/mysql.go`) writes the three principal columns; `List` drops the `LEFT JOIN users` and reads the snapshot label.
8. **Email-resolver closures** (`cmd/main.go` `userEmailByIDFromIdentity`, `rules/bootstrap` dep, detection-config handler) are removed or replaced by the principal resolver.
9. **#515 SSO stopgap** (ssoadmin nullable `*int64` threading, bootstrap apply closure) is deleted; the SSO update stamps `Principal.ID`.

## Migration mechanics (hard cutover)

Each migration is forward-only (ADR-0009). Order within identity 00005: create `principals`; backfill one row per `users` row (`usr_<id>`, label = email) and one per `service_accounts` row (`svc_<id>`, label = name) and the `sys` row; add and populate `principal_id` on both subtype tables; rewrite the attribution and audit columns with backfill; drop the legacy columns. The other contexts' migrations only rewrite their own attribution columns and values. There is no data migration across the events boundary and no dual-write window.

## Testing

- PBT round-trip for `PrincipalRef` id <-> `(type, local)` mint/parse (a serialization round-trip per the testing-strategy matrix).
- `UserID()` negative cases: it returns `(0, false)` for a `svc_`/`sys` id, a malformed `usr_` local part, and the empty string; it returns `(n, true)` only for a well-formed `usr_<n>`.
- Table-driven authenticator test: an SA token resolves to a `service_account` principal with a non-empty id and label, both read from the token claims with no DB read.
- The #518 regression test the issue asks for: a table over every authed write route exercised with a service-account actor, asserting no `actor is required` rejection and an audit row attributed to `svc_<id>`.
- Integration: a service-account SSO update, detection-config exclusion create, and app-control rule create each record the acting `svc_<id>` in both the audit row and the per-row attribution column.
- System-write test: an env-seed / background mutation records the `sys` principal (id `sys`) in the attribution column, never `NULL` or the literal `"system"`.
- Audit reader test: a deleted user's history still resolves the snapshot label with no join (the tombstoned `principals` row keeps the id resolvable).
