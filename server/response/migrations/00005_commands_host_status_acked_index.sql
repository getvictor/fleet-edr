-- +goose Up
-- Index backing the control gateway's delivery read (issue #1062), which now asks for two things at once:
--   SELECT ... FROM commands WHERE host_id IN (...) AND (status = 'pending' OR (status = 'acked' AND acked_at > ? AND acked_at <= ?))
-- The gateway runs it every second for every connected host. idx_commands_host_status (host_id, status) seeks the equality but leaves
-- the acked_at range to be applied row by row, and that range's rows are the ones that accumulate: a command whose outcome never
-- arrived stays acked for good, deliberately, since past the redelivery window the agent can no longer replay it. Without the
-- timestamp in the index, every such command a fleet has ever stranded is examined on every sweep, so the watch gets slower the
-- longer the deployment runs.
--
-- (host_id, status, acked_at) makes both halves index ranges: the pending half stops at the status prefix, the acked half seeks
-- straight to the window. It supersedes idx_commands_host_status, whose (host_id, status) is its leftmost prefix, so that index is
-- dropped in the same migration rather than left to cost every write.
--
-- Secondary-index changes, built online, so this ships single-step under ADR-0009. The algorithm and lock are stated so MySQL refuses
-- the statement rather than falling back to a plan that blocks command inserts while it builds. No down section, per the same ADR.

-- +goose StatementBegin
CREATE INDEX idx_commands_host_status_acked ON commands (host_id, status, acked_at) ALGORITHM=INPLACE LOCK=NONE;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX idx_commands_host_status ON commands ALGORITHM=INPLACE LOCK=NONE;
-- +goose StatementEnd
