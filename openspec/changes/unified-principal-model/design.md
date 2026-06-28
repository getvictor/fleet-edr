# Design: unified principal model

This is the concrete shape behind ADR-0017. It records the schema, the Go boundary types, the hard-cutover migration plan, and the per-site code changes.

## Principal identifier

A principal id is a type-prefixed opaque string, the primary key of `principals`, and the single value stored everywhere an actor is attributed.

- Prefixes: `usr_` (user), `svc_` (service account), and the singleton `sys` (the deployment itself).
- The local part is opaque: stable, unique, never reused. New rows mint a ULID local part (`usr_01J...`); the one-time backfill derives it from the existing numeric key (`usr_5`). Both are valid; nothing parses the local part except the user-id accessor below, which is only valid for `usr_` ids.
- The `type` is stored as a column too. The prefix is the self-describing wire form; the column is the authoritative, indexable discriminator. The two never disagree (a single mint helper sets both).

## Schema

### identity: `principals` (new) and references (migration 00005)

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

- `oidc_config.updated_by`, `app_config.updated_by` (FK `ON DELETE SET NULL` becomes a tombstone reference; nullable only for the never-yet-written case, defaulting to `sys` on env-seed).
- `service_accounts.created_by`.

### identity: `audit_events` (migration 00005, same file)

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

`actor_principal_id` is null only for a pre-authentication auth-failure row, which records the attempted identifier in `actor_label`. `actor_label` is a snapshot: the principal's `display_label` at the moment of the action, so a later rename or deletion does not rewrite history. No `LEFT JOIN users` on read.

### observability, rules, detection (migrations 00002 / 00003 / 00008)

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

Actor construction:

- Session middleware / `service.LoadActor`: builds `PrincipalRef{ID: "usr_"+userID, Type: user, Label: email}` from the user row.
- Service-account authenticator: builds `PrincipalRef{ID: <principal id from claims.Subject>, Type: service_account, Label: <SA name>}`. The token subject is the SA client id; the authenticator maps it to the principal id (the SA row already carries `principal_id`). This is the line that fixes #514 and #518 at the root: the principal now survives authentication.

## Principal resolution (replacing the email closures)

Audit rows snapshot the label at write time, so audit reads need no resolver. Live config views (the detection-config exclusions list) that want the *current* label resolve `principal_id -> display_label` through one identity-owned resolver exposed on `identity/api`, replacing the user-only `UserEmailByID` closure and the detection-config `userEmailResolver` / `parseUserActorID`. The resolver handles every principal type, so the UI's `created_by_email`-style field is filled for service accounts too.

## Per-site code changes

Grouped by the enumeration behind ADR-0017. Each is a hard edit to the principal model, no compatibility branch.

1. **`Actor.UserID` reads** become `Actor.Principal` reads. The user-on-user checks (`useradmin/handler.go`, `saadmin/handler.go`) use `Principal.UserID()`. The attribution stamps (`ssoadmin`, `tracingadmin`, `appcontrol/service.go`, `detectionconfig/service.go`, detection `operator/handler.go`) stamp `Principal.ID`.
2. **Actor construction** (`service.LoadActor`, `serviceaccounts/authenticator.go`) builds a `PrincipalRef`.
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
- Table-driven authenticator test: an SA token resolves to a `service_account` principal with a non-empty id and label.
- The #518 regression test the issue asks for: a table over every authed write route exercised with a service-account actor, asserting no `actor is required` rejection and an audit row attributed to `svc_<id>`.
- Integration: a service-account SSO update, detection-config exclusion create, and app-control rule create each record the acting `svc_<id>` in both the audit row and the per-row attribution column.
- Audit reader test: a deleted user's history still resolves the snapshot label with no join.
