-- +goose Up
-- +goose StatementBegin
-- commands holds the agent-bound command queue. This baseline is the response context's pre-goose schemaStatements verbatim;
-- CREATE TABLE IF NOT EXISTS keeps it safe to apply against a database that already carries the table from the legacy in-process
-- ApplySchema (the apply no-ops and goose simply records version 1).
CREATE TABLE IF NOT EXISTS commands (
	id           BIGINT AUTO_INCREMENT PRIMARY KEY,
	host_id      VARCHAR(255)  NOT NULL,
	command_type VARCHAR(64)   NOT NULL,
	payload      JSON          NOT NULL,
	status       ENUM('pending', 'acked', 'completed', 'failed') NOT NULL DEFAULT 'pending',
	created_at   TIMESTAMP(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	acked_at     TIMESTAMP(6)  NULL,
	completed_at TIMESTAMP(6)  NULL,
	result       JSON,
	INDEX idx_commands_host_status (host_id, status),
	INDEX idx_commands_created (created_at)
);
-- +goose StatementEnd
