package bootstrap

// schemaStatements are the CREATE TABLE statements the rules context
// owns. Idempotent (IF NOT EXISTS); safe to re-run on a populated DB.
// No cross-context FKs.
//
// Phase 1 of the add-application-control change dropped the legacy
// `policies` singleton table. The demo cut introduces the two
// authoritative tables of the new subsystem — `app_control_policies`
// and `app_control_rules` — plus the `Default` policy seed.
// `host_groups` and `app_control_assignments` (the other two tables in
// the full spec) are deferred to follow-on work; for the demo every
// policy implicitly targets every host in the deployment.
var schemaStatements = []string{
	// app_control_policies holds a named ruleset. The product is a single-instance deployment, so policies are unique by name across the
	// deployment. `default_action` is constrained to `NONE` in this phase; the Lockdown change extends the enum to `('NONE','BLOCK')` so a
	// per-policy default-deny stance can be set on real fleets.
	`CREATE TABLE IF NOT EXISTS app_control_policies (
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
	)`,
	// app_control_rules carries one row per rule. rule_type is the full six-value enum from the spec so the schema doesn't need a
	// migration when the other five types come online; identifier validation in the appcontrol package gates which types are actually
	// accepted by the REST surface. action is constrained to `BLOCK` in this phase; ALLOW + SILENT_BLOCK arrive with Lockdown. enforcement
	// is in the schema with the full pair so the column is ready for the Phase B Detect/Protect split. severity, source, source_ref,
	// expires_at all exist for future threat-intel and TTL work; the demo populates default values for them. The FK on policy_id is
	// intra-context (both tables live in rules), so the ADR-0004 cross-context-FK ban does not apply. CASCADE on policy delete keeps
	// orphan rules from accumulating.
	`CREATE TABLE IF NOT EXISTS app_control_rules (
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
	)`,
}
