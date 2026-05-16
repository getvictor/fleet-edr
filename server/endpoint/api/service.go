package api

import "context"

// Service is the endpoint bounded context's full business surface. The agent enroll endpoint, the host-token middleware, and the
// operator-facing listing/revoke endpoints all consume this. Other contexts that need endpoint functionality (today: cmd/main wires
// the host-token middleware into the agent route stack) call into it through this api.Service interface.
type Service interface {
	// Enroll handles the agent enroll flow: validates the enroll secret + hardware UUID, persists the enrollment row, generates a bearer
	// token, and best-effort enqueues an initial set_blocklist command. sourceIP is the resolved client IP (the caller is responsible for
	// any X-Forwarded-For handling). Returns ErrInvalidSecret on bad secret and ErrInvalidHardwareUUID on malformed UUID; both are 401/400
	// mappings the handler does.
	Enroll(ctx context.Context, req EnrollRequest, sourceIP string) (EnrollResponse, error)

	// VerifyToken resolves a presented bearer token to a host_id. Used by the HostToken middleware on every agent request. Returns
	// ErrInvalidToken on any kind of mismatch (unknown, revoked, malformed); the caller does not distinguish those cases.
	VerifyToken(ctx context.Context, token string) (string, error)

	// List returns operator-visible enrollment rows.
	List(ctx context.Context) ([]Enrollment, error)

	// Get returns a single enrollment row. Returns ErrNotFound when the
	// host_id has no enrollment.
	Get(ctx context.Context, hostID string) (*Enrollment, error)

	// Revoke marks an enrollment revoked. actor is the operator who performed the revocation (typically email or "user:<id>"). Idempotent:
	// revoking an already-revoked row preserves the original revoked_at + reason + actor (first-revoker wins). Returns ErrNotFound when
	// the host_id is not in the table at all.
	Revoke(ctx context.Context, hostID, reason, actor string) error

	// CountActive returns the count of non-revoked enrollments. Used
	// by metrics (the EnrolledHosts gauge in cmd/main).
	CountActive(ctx context.Context) (int, error)

	// ActiveHostIDs returns the non-revoked host_ids in stable order.
	// Used by the policy fan-out path.
	ActiveHostIDs(ctx context.Context) ([]string, error)

	// RotateToken atomically issues a fresh bearer token for hostID, moves
	// the prior token into the grace-window slot (so an in-flight agent
	// poll doesn't 401 mid-cycle), and queues a rotate_token command that
	// delivers the new token to the agent on its next poll. Returns
	// ErrNotFound when the host_id has no enrollment.
	//
	// trigger names who initiated the rotation; actor + reason are the
	// operator-supplied attribution carried into the audit row when
	// trigger == RotationTriggerOperator (both empty for auto). The raw
	// new token is intentionally not in the response: the agent gets it
	// via the rotate_token command, and exposing it via the operator API
	// would invite copy-paste flows that bypass the command queue.
	RotateToken(ctx context.Context, hostID string, trigger RotationTrigger, actor, reason string) (RotateResult, error)
}
