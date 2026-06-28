-- +goose Up
-- The unified principal model (ADR-0017, issues #514 + #518). A principal is the single typed identity every authenticated actor
-- resolves to: a human user, a service account, or the deployment itself. This migration creates the principals spine, backfills one
-- row per existing user / service account plus the singleton system principal, and rewrites every identity-context attribution column
-- (and the audit trail) from a user-only BIGINT to the principal id string. Hard cutover: the legacy BIGINT columns are dropped, not
-- kept alongside (the product is pre-release, so there is no attribution history to preserve).

-- +goose StatementBegin
-- principals is the identity spine. id is a type-prefixed string (usr_<users.id> / svc_<service_accounts.id> / the singleton 'sys');
-- type is the authoritative discriminator (also encoded in the id prefix); display_label is the snapshot-able name (user email, SA
-- name, or 'system'); disabled_at tombstones a removed subtype row so attribution stays resolvable and the id is never reused.
CREATE TABLE IF NOT EXISTS principals (
	id            VARCHAR(40)  NOT NULL,
	type          ENUM('user', 'service_account', 'system') NOT NULL,
	display_label VARCHAR(255) NOT NULL,
	disabled_at   TIMESTAMP(6) NULL,
	created_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	PRIMARY KEY (id),
	INDEX idx_principals_type (type)
);
-- +goose StatementEnd

-- +goose StatementBegin
-- The singleton system principal: env-seed writes, background jobs, and migrations attribute to it rather than to NULL or a free-form
-- 'system' literal.
INSERT INTO principals (id, type, display_label) VALUES ('sys', 'system', 'system')
ON DUPLICATE KEY UPDATE display_label = VALUES(display_label);
-- +goose StatementEnd

-- +goose StatementBegin
-- One principal per existing user.
INSERT INTO principals (id, type, display_label)
SELECT CONCAT('usr_', id), 'user', email FROM users
ON DUPLICATE KEY UPDATE display_label = VALUES(display_label);
-- +goose StatementEnd

-- +goose StatementBegin
-- One principal per existing service account.
INSERT INTO principals (id, type, display_label)
SELECT CONCAT('svc_', id), 'service_account', name FROM service_accounts
ON DUPLICATE KEY UPDATE display_label = VALUES(display_label);
-- +goose StatementEnd

-- NOTE: the BIGINT-FK attribution columns (oidc_config.updated_by, app_config.updated_by, service_accounts.created_by) are rewritten to
-- the principal id in the following migration (00006), paired with the store-layer threading; this migration lands the spine + the audit
-- trail so the principal model is established first.

-- audit_events: replace the user-only actor_user_id + actor_email with a typed principal triple (type, principal id, snapshot label).
-- actor_principal_id is deliberately unconstrained (no FK): the append-only audit history must never be invalidated by a deleted
-- principal or a later widening of the type set. A pre-auth failure row keeps a NULL principal id and records the attempted identifier
-- in actor_label.
-- +goose StatementBegin
ALTER TABLE audit_events
	ADD COLUMN actor_type         VARCHAR(32)  NULL AFTER occurred_at,
	ADD COLUMN actor_principal_id VARCHAR(40)  NULL AFTER actor_type,
	ADD COLUMN actor_label        VARCHAR(255) NULL AFTER actor_principal_id;
-- +goose StatementEnd
-- +goose StatementBegin
-- A legacy row with actor_user_id = 0 carried no real user (pre-auth failures and the old service-account 0 stopgap), so it backfills to
-- no principal (NULL id/type) with the attempted identifier preserved in actor_label, never the bogus usr_0.
UPDATE audit_events SET
	actor_principal_id = CASE WHEN actor_user_id IS NULL OR actor_user_id = 0 THEN NULL ELSE CONCAT('usr_', actor_user_id) END,
	actor_type = CASE WHEN actor_user_id IS NULL OR actor_user_id = 0 THEN NULL ELSE 'user' END,
	actor_label = actor_email;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE audit_events DROP INDEX idx_audit_events_actor;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE audit_events DROP COLUMN actor_user_id, DROP COLUMN actor_email;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE audit_events ADD INDEX idx_audit_events_actor (actor_principal_id, occurred_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd
