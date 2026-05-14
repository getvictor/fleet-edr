package bootstrap

// schemaStatements creates the five tables detection owns: events,
// processes, alerts, alert_events, hosts. CREATE TABLE IF NOT EXISTS
// so re-running ApplySchema is idempotent.
//
// Note: alerts.updated_by has NO FK to users(id). The alert-update
// service layer enforces user existence via the UserExists closure
// the response context wires in at bootstrap time, so the chokepoint
// catches an orphan user_id without taking a cross-context FK
// dependency in the schema.
var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS events (
		event_id        VARCHAR(255) PRIMARY KEY,
		host_id         VARCHAR(255) NOT NULL,
		timestamp_ns    BIGINT       NOT NULL,
		ingested_at_ns  BIGINT       NOT NULL DEFAULT 0,
		event_type      VARCHAR(64)  NOT NULL,
		payload         JSON         NOT NULL,
		payload_pid     BIGINT       GENERATED ALWAYS AS (CAST(JSON_UNQUOTE(JSON_EXTRACT(payload, '$.pid')) AS UNSIGNED)) STORED,
		processed       TINYINT(1)   NOT NULL DEFAULT 0,
		created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
		INDEX idx_events_host_id (host_id),
		INDEX idx_events_type (event_type),
		INDEX idx_events_timestamp (timestamp_ns),
		INDEX idx_events_host_type_ingested (host_id, event_type, ingested_at_ns),
		INDEX idx_events_host_type_pid_ingested (host_id, event_type, payload_pid, ingested_at_ns),
		INDEX idx_events_processed (processed, host_id, timestamp_ns)
	)`,
	`CREATE TABLE IF NOT EXISTS processes (
		id                   BIGINT AUTO_INCREMENT PRIMARY KEY,
		host_id              VARCHAR(255) NOT NULL,
		pid                  INT          NOT NULL,
		ppid                 INT          NOT NULL,
		path                 TEXT         NOT NULL,
		args                 JSON,
		uid                  INT,
		gid                  INT,
		code_signing         JSON,
		sha256               VARCHAR(64),
		fork_time_ns         BIGINT       NOT NULL,
		fork_ingested_at_ns  BIGINT,
		exec_time_ns         BIGINT,
		exit_time_ns         BIGINT,
		exit_ingested_at_ns  BIGINT,
		exit_reason          VARCHAR(32),
		exit_code            INT,
		previous_exec_id     BIGINT,
		INDEX idx_processes_host_pid (host_id, pid, fork_time_ns),
		INDEX idx_processes_host_ppid (host_id, ppid, fork_time_ns),
		INDEX idx_processes_host_time (host_id, fork_time_ns),
		INDEX idx_processes_previous_exec (previous_exec_id)
	)`,
	`CREATE TABLE IF NOT EXISTS alerts (
		id           BIGINT AUTO_INCREMENT PRIMARY KEY,
		host_id      VARCHAR(255) NOT NULL,
		rule_id      VARCHAR(64)  NOT NULL,
		source       ENUM('detection', 'application_control') NOT NULL DEFAULT 'detection',
		severity     ENUM('low', 'medium', 'high', 'critical') NOT NULL,
		title        VARCHAR(512) NOT NULL,
		description  TEXT         NOT NULL,
		process_id   BIGINT       NOT NULL,
		techniques   JSON         NULL,
		status       ENUM('open', 'acknowledged', 'resolved') NOT NULL DEFAULT 'open',
		updated_by   BIGINT       NULL,
		created_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		updated_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
		resolved_at  TIMESTAMP(6) NULL,
		UNIQUE KEY uk_alerts_dedup (source, host_id, rule_id, process_id),
		INDEX idx_alerts_host (host_id),
		INDEX idx_alerts_status_created (status, created_at),
		INDEX idx_alerts_updated_by (updated_by),
		INDEX idx_alerts_source_created (source, created_at),
		CONSTRAINT fk_alerts_process FOREIGN KEY (process_id) REFERENCES processes(id)
	)`,
	`CREATE TABLE IF NOT EXISTS alert_events (
		alert_id  BIGINT       NOT NULL,
		event_id  VARCHAR(255) NOT NULL,
		PRIMARY KEY (alert_id, event_id),
		CONSTRAINT fk_ae_alert FOREIGN KEY (alert_id) REFERENCES alerts(id),
		CONSTRAINT fk_ae_event FOREIGN KEY (event_id) REFERENCES events(event_id)
	)`,
	`CREATE TABLE IF NOT EXISTS hosts (
		host_id      VARCHAR(255) PRIMARY KEY,
		event_count  BIGINT       NOT NULL DEFAULT 0,
		last_seen_ns BIGINT       NOT NULL DEFAULT 0,
		updated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
	)`,
}
