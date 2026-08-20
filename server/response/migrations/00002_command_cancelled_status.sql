-- +goose Up
-- Add the two terminal states a command can reach without any agent ever running it: withdrawn by an operator, and aged out.
--
-- A command can sit pending indefinitely: the host may be offline, or it may be holding a control stream the server has forgotten
-- (issue #711). There was no way to withdraw one, and a pid-addressed kill delivered long after it was issued can land on a recycled
-- pid and terminate an unrelated process. `cancelled` is distinct from `failed` on purpose: failed means an agent tried and could not,
-- while cancelled means no agent ever saw it, and an operator auditing what ran on a host needs to tell those apart.
--
-- `expired` is the same idea reached by time rather than by an operator: a command that has waited past its delivery window is aged
-- out instead of being handed to an agent late. Both are distinct from `failed`, which means an agent tried and could not, and both
-- are reachable only from `pending`: once a command is acked the agent owns it and may already have applied the side effect, so
-- recording either would misreport what happened on the host.
ALTER TABLE commands
	MODIFY COLUMN status ENUM('pending', 'acked', 'completed', 'failed', 'cancelled', 'expired') NOT NULL DEFAULT 'pending';

-- +goose Down
ALTER TABLE commands MODIFY COLUMN status ENUM('pending', 'acked', 'completed', 'failed') NOT NULL DEFAULT 'pending';
