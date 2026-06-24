package api

import "context"

// Service is the response-context surface for the agent command
// queue. Consumed by:
//   - response/internal/agent: GET /api/commands and
//     PUT /api/commands/{id};
//   - response/internal/operator: POST /api/commands and
//     GET /api/commands/{id};
//   - endpoint/internal/service: Insert at enroll-fan-out time,
//     via a method-value closure;
//   - rules/internal/appcontrol: InsertBatch at app-control policy
//     fan-out time, via a method-value closure;
//   - cmd/main metrics adapter: CountPending for the
//     PendingCommands gauge.
//
// Endpoint consumes the single-row Insert and rules consumes the
// batched InsertBatch as method values satisfying their closure
// types; neither imports response/api directly.
type Service interface {
	// Insert appends a command row. Returns the new id. Validation errors (empty hostID/commandType, empty payload) wrap
	// ErrInvalidInsertRequest.
	Insert(ctx context.Context, hostID, commandType string, payload []byte) (int64, error)

	// InsertBatch appends one command row per host_id, all sharing commandType + payload, via a chunked multi-row INSERT.
	// Returns the number of rows that landed. The application-control fan-out consumes this as a method value so a policy
	// mutation enqueues the whole assigned host set in a couple of round trips rather than one per host. Validation errors
	// (empty hostIDs, commandType, or payload) wrap ErrInvalidInsertRequest.
	InsertBatch(ctx context.Context, hostIDs []string, commandType string, payload []byte) (int, error)

	// Get returns a single command by id. Operator-only path: agents should use ListForHost. Returns ErrCommandNotFound for an unknown
	// id.
	Get(ctx context.Context, id int64) (Command, error)

	// ListForHost returns commands for the pinned host_id, optionally
	// filtered by status (empty string returns every status). Agent
	// hot path: called every 5s per host.
	//
	// Side effect: calls the Heartbeat closure (wired by cmd/main) so
	// the host's last-seen-ns advances on every poll. The closure
	// pattern keeps response free of an explicit detection dependency.
	ListForHost(ctx context.Context, hostID string, status Status) ([]Command, error)

	// UpdateStatus transitions a command's status. Agent-driven (acks its commands) but takes the pinned host_id from req so the service
	// can reject cross-host updates with ErrCommandNotFound. Returns ErrInvalidStatusTransition for illegal transitions.
	UpdateStatus(ctx context.Context, req UpdateStatusRequest) error

	// CountPending returns the count of pending commands across every host. Used by the OTel metrics gauge so SOC dashboards can alert on
	// stuck-poll fleets.
	CountPending(ctx context.Context) (int, error)
}
