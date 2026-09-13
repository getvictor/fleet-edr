-- +goose Up
-- Index backing the watched-path catch-up's read of each host's latest command of a type (issue #998):
--   SELECT host_id, MAX(id) FROM commands WHERE command_type = ? AND host_id IN (...) GROUP BY host_id
-- It runs every few minutes for every enrolled host, and command history is not pruned, so without this the read grows with every
-- command a host has ever been sent. idx_commands_host_status (host_id, status) serves only the host_id equality here, since status is
-- not filtered, and leaves each host's whole history to scan for the type. (host_id, command_type, id) makes MAX(id) for a host and type
-- the last entry of an index range.
--
-- A secondary-index add, built online, so it ships single-step under ADR-0009. The algorithm and lock are stated so MySQL refuses the
-- statement rather than falling back to a plan that blocks command inserts while it builds. No down section, per the same ADR.

-- +goose StatementBegin
CREATE INDEX idx_commands_host_type_id ON commands (host_id, command_type, id) ALGORITHM=INPLACE LOCK=NONE;
-- +goose StatementEnd
