package api

import "context"

// Service is the endpoint bounded context's full business surface. The agent enroll endpoint, the host-token middleware, and the
// operator-facing listing/revoke endpoints all consume this. Other contexts that need endpoint functionality (today: cmd/main wires
// the host-token middleware into the agent route stack) call into it through this api.Service interface.
type Service interface {
	// Enroll handles the agent enroll flow: validates the enroll secret + hardware UUID, persists the enrollment row, and mints a
	// self-validating signed bearer token. sourceIP is the resolved client IP (the caller is responsible for any X-Forwarded-For
	// handling). Returns ErrInvalidSecret on bad secret and ErrInvalidHardwareUUID on malformed UUID; both are 401/400 mappings the
	// handler does.
	Enroll(ctx context.Context, req EnrollRequest, sourceIP string) (EnrollResponse, error)

	// VerifyToken resolves a presented bearer token to a host_id. Used by the HostToken middleware on every agent request. The token is
	// self-validating (local signature + expiry check); revocation is enforced via an in-memory snapshot, so this does no database
	// lookup. Returns ErrInvalidToken on any kind of mismatch (unknown, revoked, expired, malformed); the caller does not distinguish
	// those cases, which would be an oracle.
	VerifyToken(ctx context.Context, token string) (string, error)

	// RefreshToken issues a fresh signed token for the host_id pinned on ctx by the HostToken middleware. The agent calls this before its
	// current token expires so a live host never lapses. Returns ErrInvalidToken when the host is unknown or revoked (the handler maps
	// that to 401, prompting the agent to re-enroll).
	RefreshToken(ctx context.Context) (RefreshResponse, error)

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

	// RotateToken cycles a host's credentials by bumping its token_epoch, invalidating every signed token minted at the prior epoch once
	// the revocation snapshot picks up the change. Under the self-validating-token model there is no opaque token to rotate and no
	// command to push: the agent recovers by re-enrolling when its refresh (carrying the now-stale epoch) 401s. trigger names who
	// initiated it; actor + reason are the operator-supplied attribution carried into the audit row. Returns ErrNotFound when the
	// host_id has no enrollment. The returned RotateResult is empty (no token/command under this model).
	RotateToken(ctx context.Context, hostID string, trigger RotationTrigger, actor, reason string) (RotateResult, error)
}
