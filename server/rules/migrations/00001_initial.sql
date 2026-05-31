-- +goose Up
-- The rules context's Application Control tables. This baseline is the pre-goose schemaStatements verbatim; CREATE TABLE IF NOT
-- EXISTS keeps it safe to apply against a database that already carries the tables (the apply no-ops and goose records version 1).
-- No cross-context FKs; all FKs here are intra-context (rules owns every referenced table).
--
-- Order is load-bearing: app_control_policies and host_groups before the tables that reference them. Phase A ships four tables;
-- the built-in all-hosts group and the Default -> all-hosts assignment are seeded by bootstrap, not by this corpus.

-- +goose StatementBegin
-- app_control_policies holds a named ruleset. The product is a single-instance deployment, so policies are unique by name across the
-- deployment. default_action is constrained to NONE in this phase; the Lockdown change extends the enum to ('NONE','BLOCK') so a
-- per-policy default-deny stance can be set on real fleets.
CREATE TABLE IF NOT EXISTS app_control_policies (
	id             BIGINT AUTO_INCREMENT PRIMARY KEY,
	name           VARCHAR(64)  NOT NULL,
	description    VARCHAR(255) NOT NULL DEFAULT '',
	version        BIGINT       NOT NULL DEFAULT 1,
	default_action ENUM('NONE') NOT NULL DEFAULT 'NONE',
	created_at     TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	updated_at     TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
	created_by     VARCHAR(255) NOT NULL DEFAULT 'system',
	updated_by     VARCHAR(255) NOT NULL DEFAULT 'system',
	UNIQUE KEY uk_app_control_policies_name (name)
);
-- +goose StatementEnd

-- +goose StatementBegin
-- app_control_rules carries one row per rule. rule_type is the full six-value enum from the spec so the schema doesn't need a
-- migration when the other five types come online; identifier validation in the appcontrol package gates which types are actually
-- accepted by the REST surface. action is constrained to BLOCK in this phase; ALLOW + SILENT_BLOCK arrive with Lockdown. enforcement
-- is in the schema with the full pair so the column is ready for the Phase B Detect/Protect split. severity, source, source_ref,
-- expires_at all exist for future threat-intel and TTL work; the demo populates default values for them. The FK on policy_id is
-- intra-context (both tables live in rules). CASCADE on policy delete keeps orphan rules from accumulating.
CREATE TABLE IF NOT EXISTS app_control_rules (
	id           BIGINT AUTO_INCREMENT PRIMARY KEY,
	policy_id    BIGINT       NOT NULL,
	rule_type    ENUM('CDHASH','BINARY','SIGNINGID','CERTIFICATE','TEAMID','PATH') NOT NULL,
	identifier   VARCHAR(255) NOT NULL,
	action       ENUM('BLOCK') NOT NULL DEFAULT 'BLOCK',
	enforcement  ENUM('PROTECT','DETECT') NOT NULL DEFAULT 'PROTECT',
	enabled      TINYINT(1)   NOT NULL DEFAULT 1,
	severity     ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
	source       ENUM('admin','imported','intel') NOT NULL DEFAULT 'admin',
	source_ref   VARCHAR(255) NOT NULL DEFAULT '',
	custom_msg   VARCHAR(500) NULL,
	custom_url   VARCHAR(500) NULL,
	comment      VARCHAR(500) NOT NULL DEFAULT '',
	expires_at   TIMESTAMP(6) NULL,
	created_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	updated_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
	created_by   VARCHAR(255) NOT NULL DEFAULT 'system',
	UNIQUE KEY uk_app_control_rules_policy_type_id (policy_id, rule_type, identifier),
	INDEX idx_app_control_rules_policy (policy_id),
	INDEX idx_app_control_rules_type_id (rule_type, identifier),
	CONSTRAINT fk_app_control_rules_policy FOREIGN KEY (policy_id)
		REFERENCES app_control_policies(id) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose StatementBegin
-- host_groups is the named, deployment-wide host-membership unit. criteria is a JSON document the bootstrap seeds with
-- {"type":"all"} for the built-in all-hosts row, and that future Phase B work extends with tag/hostname/OS predicates without a
-- schema migration. Phase A only ever creates the seed row; user-authored groups arrive in Phase B. Name is deployment-unique so the
-- REST surface can address groups by name without exposing the integer id.
CREATE TABLE IF NOT EXISTS host_groups (
	id          BIGINT AUTO_INCREMENT PRIMARY KEY,
	name        VARCHAR(64)  NOT NULL,
	description VARCHAR(255) NOT NULL DEFAULT '',
	criteria    JSON         NOT NULL,
	created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	updated_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
	UNIQUE KEY uk_host_groups_name (name)
);
-- +goose StatementEnd

-- +goose StatementBegin
-- app_control_assignments is the policy -> host-group many-to-many. priority is reserved for Phase B conflict resolution when two
-- policies are assigned to overlapping groups; Phase A only ever has one assignment row. CASCADE on both FK sides keeps an
-- orphan-free state if either side is deleted; both FKs are intra-context so ADR-0004's no-cross-context-FK rule does not apply.
CREATE TABLE IF NOT EXISTS app_control_assignments (
	policy_id     BIGINT       NOT NULL,
	host_group_id BIGINT       NOT NULL,
	priority      INT          NOT NULL DEFAULT 0,
	created_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	PRIMARY KEY (policy_id, host_group_id),
	INDEX idx_app_control_assignments_group (host_group_id),
	CONSTRAINT fk_app_control_assignments_policy FOREIGN KEY (policy_id)
		REFERENCES app_control_policies(id) ON DELETE CASCADE,
	CONSTRAINT fk_app_control_assignments_group FOREIGN KEY (host_group_id)
		REFERENCES host_groups(id) ON DELETE CASCADE
);
-- +goose StatementEnd
