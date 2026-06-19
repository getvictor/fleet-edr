// Public types for the endpoint bounded context. See the package doc in doc.go.

package api

import (
	"errors"
	"time"
)

// Enrollment mirrors the operator-visible row from the enrollments table. The token hash + salt are intentionally omitted; callers
// that need to verify a token go through Service.VerifyToken, not direct row access.
type Enrollment struct {
	HostID       string     `db:"host_id" json:"host_id"`
	Hostname     string     `db:"hostname" json:"hostname"`
	AgentVersion string     `db:"agent_version" json:"agent_version"`
	OSVersion    string     `db:"os_version" json:"os_version"`
	SourceIP     string     `db:"source_ip" json:"source_ip"`
	EnrolledAt   time.Time  `db:"enrolled_at" json:"enrolled_at"`
	ExpiresAt    *time.Time `db:"expires_at" json:"expires_at,omitempty"`
	RevokedAt    *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`
	RevokeReason *string    `db:"revoke_reason" json:"revoke_reason,omitempty"`
	RevokedBy    *string    `db:"revoked_by" json:"revoked_by,omitempty"`
}

// EnrollRequest is the wire payload the agent POSTs at /api/enroll. Field names + JSON tags preserved exactly across the
// modular-monolith migration; the agent contract is byte-identical with main.
type EnrollRequest struct {
	EnrollSecret string `json:"enroll_secret"`
	HardwareUUID string `json:"hardware_uuid"`
	Hostname     string `json:"hostname"`
	OSVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
}

// EnrollResponse is what the agent receives. HostToken is a self-validating signed token (see internal/signedtoken): it carries the
// host_id, epoch, and expiry, signed with a server-held key, so subsequent verification is a local signature check with no database
// lookup. ExpiresAt is the token's absolute expiry; the agent refreshes via POST /api/token/refresh before it is reached.
type EnrollResponse struct {
	HostID     string    `json:"host_id"`
	HostToken  string    `json:"host_token"`
	EnrolledAt time.Time `json:"enrolled_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// RefreshResponse is returned by POST /api/token/refresh: a freshly minted signed token for the already-authenticated host plus its new
// expiry. host_id echoes the authenticated identity for symmetry with enroll; the agent keeps its existing host_id and swaps only the
// token + expiry.
type RefreshResponse struct {
	HostID    string    `json:"host_id"`
	HostToken string    `json:"host_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Errors returned across the api boundary. Callers compare with errors.Is.
var (
	// ErrInvalidSecret is returned when the agent's enroll_secret doesn't
	// match the configured value. Mapped to 401 by the enroll handler.
	ErrInvalidSecret = errors.New("endpoint: invalid enroll secret")

	// ErrInvalidToken is returned when a presented bearer token does not resolve to an active enrollment (unknown, revoked, or malformed).
	// Callers do not get to distinguish those cases; that would be an oracle for token-still-active probing.
	ErrInvalidToken = errors.New("endpoint: invalid host token")

	// ErrInvalidHardwareUUID is returned when the agent presents an
	// unparseable hardware UUID. Mapped to 400.
	ErrInvalidHardwareUUID = errors.New("endpoint: invalid hardware uuid")

	// ErrInvalidEnrollRequest is returned when one or more required fields of the EnrollRequest are blank (enroll_secret, hardware_uuid,
	// hostname, os_version, agent_version). Mapped to 400 by the HTTP handler. A separate sentinel from ErrInvalidSecret so non-HTTP
	// callers (tests, future contexts) can distinguish "shape" from "credential" without parsing free-form error strings.
	ErrInvalidEnrollRequest = errors.New("endpoint: invalid enroll request")

	// ErrNotFound is returned by Get / Revoke when the host_id has no
	// enrollment row.
	ErrNotFound = errors.New("endpoint: enrollment not found")
)
