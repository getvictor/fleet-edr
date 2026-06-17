-- +goose Up
-- Carry the kernel PID generation (pidversion, from audit_token_to_pidversion) on each process record so network_connect /
-- dns_query flows can correlate to the exact process generation by identity (host_id, pid, pidversion) rather than by a
-- fork-to-exit time window. PID reuse recycles a pid; pidversion is the kernel field that disambiguates a recycled pid, so an
-- exact (host_id, pid, pidversion) match is immune to the boundary mis-correlation the time-window join can suffer, and it
-- removes the need for the ES/NE clock-drift forward pad on the lookup (issue #7, issue #403).
--
-- Nullable on purpose: an agent that predates this field, a snapshot/exec-without-fork row whose token was unavailable, or a
-- flow with no usable audit token all leave pidversion NULL, and correlation falls back to the existing time-window path. A
-- present value of 0 is a legitimate kernel generation, which is why absence is encoded as NULL, not a 0 sentinel. INT UNSIGNED
-- matches the uid/gid widening rationale (audit_token_to_pidversion returns a uint32).

-- +goose StatementBegin
ALTER TABLE processes
	ADD COLUMN pidversion INT UNSIGNED NULL;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_processes_host_pid_pidversion ON processes (host_id, pid, pidversion);
-- +goose StatementEnd

-- +goose Down
-- Forward-only migrations (ADR-0009). Dropping the column/index would lose the identity correlation on every existing row; this
-- Down is intentionally a no-op.
