package bootstrap

// schemaStatements are the CREATE TABLE statements response owns.
// Idempotent (IF NOT EXISTS); safe to re-run on a populated DB. No
// FKs.
//
// Authoritative copy of the commands table DDL. The product hasn't
// shipped, so wave-1 column adds (notably tenant_id) live inline in
// CREATE TABLE rather than as ALTER deltas.
var schemaStatements = []string{
	// commands holds the agent-bound command queue. tenant_id is wave-1
	// scaffolding for MSSP-style multi-tenancy; wave-1 reads do NOT
	// filter on it, the column + index let wave 2 turn on tenant-aware
	// reads without a backfill.
	`CREATE TABLE IF NOT EXISTS commands (
		id           BIGINT AUTO_INCREMENT PRIMARY KEY,
		host_id      VARCHAR(255)  NOT NULL,
		command_type VARCHAR(64)   NOT NULL,
		payload      JSON          NOT NULL,
		tenant_id    VARCHAR(64)   NOT NULL DEFAULT 'default',
		status       ENUM('pending', 'acked', 'completed', 'failed') NOT NULL DEFAULT 'pending',
		created_at   TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		acked_at     TIMESTAMP(6)  NULL,
		completed_at TIMESTAMP(6)  NULL,
		result       JSON,
		INDEX idx_commands_host_status (host_id, status),
		INDEX idx_commands_created (created_at),
		INDEX idx_commands_tenant_id (tenant_id)
	)`,
}
