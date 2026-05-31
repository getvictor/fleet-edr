-- +goose Up
-- The detection context's five tables: events, processes, alerts, alert_events, hosts. This baseline is the pre-goose
-- schemaStatements verbatim (it already folds the is_snapshot / last_seen_ns / cdhash additive ALTERs into the processes CREATE,
-- so the legacy applyAdditiveAlters runner is retired with goose). CREATE TABLE IF NOT EXISTS keeps it safe to apply against a
-- database that already carries the tables: the apply no-ops and goose records version 1.
--
-- alerts.updated_by has NO FK to users(id): the alert-update service enforces user existence via the UserExists closure the
-- response context wires at bootstrap, so the chokepoint catches an orphan user_id without taking a cross-context FK.

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS events (
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
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS processes (
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
	cdhash               VARCHAR(40),
	fork_time_ns         BIGINT       NOT NULL,
	fork_ingested_at_ns  BIGINT,
	exec_time_ns         BIGINT,
	exit_time_ns         BIGINT,
	exit_ingested_at_ns  BIGINT,
	exit_reason          VARCHAR(32),
	exit_code            INT,
	previous_exec_id     BIGINT,
	is_snapshot          BOOL         NOT NULL DEFAULT FALSE,
	last_seen_ns         BIGINT,
	INDEX idx_processes_host_pid (host_id, pid, fork_time_ns),
	INDEX idx_processes_host_ppid (host_id, ppid, fork_time_ns),
	INDEX idx_processes_host_time (host_id, fork_time_ns),
	INDEX idx_processes_previous_exec (previous_exec_id),
	INDEX idx_processes_snapshot_lastseen (is_snapshot, last_seen_ns)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS alerts (
	id           BIGINT AUTO_INCREMENT PRIMARY KEY,
	host_id      VARCHAR(255) NOT NULL,
	rule_id      VARCHAR(64)  NOT NULL,
	source       ENUM('detection', 'application_control') NOT NULL DEFAULT 'detection',
	severity     ENUM('low', 'medium', 'high', 'critical') NOT NULL,
	title        VARCHAR(512) NOT NULL,
	description  TEXT         NOT NULL,
	-- process_id is a NULLABLE enrichment link (ADR-0008 amendment). Persistence alerts keyed on BTM registration
	-- have no useful live attacker process (the BTM instigator is Apple's smd), so they carry a NULL process_id; the
	-- evidence of record is the registered item, not a process. A NULL value on the FK column is permitted.
	process_id   BIGINT       NULL,
	-- subject is the dedup identity, set by the engine: the process_id as a string for process-backed alerts (which
	-- preserves the prior (source, host_id, rule_id, process_id) dedup), or a rule-supplied key (e.g.
	-- "launchdaemon:<plist>") for process-less alerts. NOT NULL so the unique key dedups (a NULL in the key would not).
	-- VARCHAR(255), not 512: it rides the uk_alerts_dedup unique key, which must stay under InnoDB's 3072-byte cap
	-- alongside host_id(255) + rule_id(64) at utf8mb4. 255 chars covers a process_id string or a namespaced path key.
	subject      VARCHAR(255) NOT NULL DEFAULT '',
	techniques   JSON         NULL,
	status       ENUM('open', 'acknowledged', 'resolved') NOT NULL DEFAULT 'open',
	updated_by   BIGINT       NULL,
	created_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	updated_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
	resolved_at  TIMESTAMP(6) NULL,
	UNIQUE KEY uk_alerts_dedup (source, host_id, rule_id, subject),
	INDEX idx_alerts_host (host_id),
	INDEX idx_alerts_status_created (status, created_at),
	INDEX idx_alerts_updated_by (updated_by),
	INDEX idx_alerts_source_created (source, created_at),
	CONSTRAINT fk_alerts_process FOREIGN KEY (process_id) REFERENCES processes(id)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS alert_events (
	alert_id  BIGINT       NOT NULL,
	event_id  VARCHAR(255) NOT NULL,
	PRIMARY KEY (alert_id, event_id),
	CONSTRAINT fk_ae_alert FOREIGN KEY (alert_id) REFERENCES alerts(id),
	CONSTRAINT fk_ae_event FOREIGN KEY (event_id) REFERENCES events(event_id)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS hosts (
	host_id      VARCHAR(255) PRIMARY KEY,
	event_count  BIGINT       NOT NULL DEFAULT 0,
	last_seen_ns BIGINT       NOT NULL DEFAULT 0,
	updated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
-- +goose StatementEnd
