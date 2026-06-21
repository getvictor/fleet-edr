-- +goose Up
-- Detection configuration surface (issue #459): the DB-backed replacement for the boot-time env-CSV allowlists + disabled-rule
-- list. Two layers: per-rule settings (mode / severity override / JSON settings) and typed false-positive exclusions. Both carry a
-- host_group_id where 0 = global scope (the api.GlobalScope sentinel); a real group id scopes the record to that host group. The
-- sentinel (rather than a nullable column) keeps the (rule_id, host_group_id) uniqueness honest for the global row AND avoids
-- InnoDB's restriction against ON DELETE referential actions on a column that backs a stored generated column. host_group_id is NOT
-- FK-constrained here: group editing is Phase A immutable (only the seeded all-hosts group exists), so existence is validated at the
-- app layer; the FK + cascade cleanup land with the editable-host-groups (Phase B) change. detection_config_meta holds a single
-- version counter the store bumps on every mutation so each replica can detect a change and reload its in-memory snapshot.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS detection_rule_settings (
	id                BIGINT AUTO_INCREMENT PRIMARY KEY,
	rule_id           VARCHAR(64) NOT NULL,
	host_group_id     BIGINT      NOT NULL DEFAULT 0,
	mode              ENUM('alert','monitor','disabled') NOT NULL DEFAULT 'alert',
	severity_override ENUM('low','medium','high','critical') NULL,
	settings          JSON         NULL,
	created_at        TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	updated_at        TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
	updated_by        VARCHAR(255) NOT NULL DEFAULT 'system',
	-- The unique key's leftmost prefix (rule_id) already serves rule_id-only lookups, so no separate single-column index is needed.
	UNIQUE KEY uk_detection_rule_settings_rule_scope (rule_id, host_group_id)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS detection_exclusions (
	id            BIGINT AUTO_INCREMENT PRIMARY KEY,
	rule_id       VARCHAR(64)  NOT NULL DEFAULT '',
	match_type    ENUM('path_glob','parent_path_glob','team_id','signing_id','cdhash','sha256','command_substring','domain') NOT NULL,
	value         VARCHAR(1024) NOT NULL,
	host_group_id BIGINT       NOT NULL DEFAULT 0,
	reason        VARCHAR(500) NOT NULL DEFAULT '',
	enabled       TINYINT(1)   NOT NULL DEFAULT 1,
	-- DATETIME (not TIMESTAMP) so a far-future expiry is not capped at the TIMESTAMP Year-2038 ceiling.
	expires_at    DATETIME(6)  NULL,
	created_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	created_by    VARCHAR(255) NOT NULL DEFAULT 'system',
	INDEX idx_detection_exclusions_rule_type (rule_id, match_type)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS detection_config_meta (
	id      TINYINT NOT NULL PRIMARY KEY,
	version BIGINT  NOT NULL DEFAULT 0
);
-- +goose StatementEnd

-- +goose StatementBegin
INSERT IGNORE INTO detection_config_meta (id, version) VALUES (1, 0);
-- +goose StatementEnd
