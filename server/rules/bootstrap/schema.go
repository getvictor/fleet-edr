package bootstrap

// schemaStatements are the CREATE TABLE + seed statements rules owns.
// Idempotent (IF NOT EXISTS / INSERT IGNORE); safe to re-run on a
// populated DB. No cross-context FKs.
//
// Authoritative copy of the policies table DDL. Earlier server
// versions inlined this in server/store/store.go's applySchema; the
// bounded-context split moved it here.
var schemaStatements = []string{
	// policies holds the server-driven blocklist. For MVP we keep a
	// single "default" row -- `name` is a UNIQUE key so v1.1 can add
	// per-team targeting without a schema migration. `version` is a
	// monotonically-increasing integer bumped on every admin PUT;
	// agents cache the last-applied version and skip no-op updates.
	`CREATE TABLE IF NOT EXISTS policies (
		id          BIGINT AUTO_INCREMENT PRIMARY KEY,
		name        VARCHAR(64)  NOT NULL,
		version     BIGINT       NOT NULL DEFAULT 1,
		blocklist   JSON         NOT NULL,
		updated_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		updated_by  VARCHAR(255) NOT NULL DEFAULT 'system',
		UNIQUE KEY uk_policies_name (name)
	)`,
	// Seed the default policy row. Using INSERT IGNORE so restarts
	// don't clobber an edited row. The initial blocklist is empty --
	// operators opt in to blocking via PUT.
	`INSERT IGNORE INTO policies (name, version, blocklist, updated_by)
	 VALUES ('default', 1, JSON_OBJECT('paths', JSON_ARRAY(), 'hashes', JSON_ARRAY()), 'system')`,
}
