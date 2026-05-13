// Public types for the endpoint bounded context. See the package doc in doc.go.

package api

import (
	"errors"
	"time"
)

// Enrollment mirrors the operator-visible row from the enrollments table.
// The token hash + salt are intentionally omitted; callers that need to
// verify a token go through Service.VerifyToken, not direct row access.
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

// EnrollRequest is the wire payload the agent POSTs at /api/enroll.
// Field names + JSON tags preserved exactly across the modular-monolith
// migration; the agent contract is byte-identical with main.
type EnrollRequest struct {
	EnrollSecret string `json:"enroll_secret"`
	HardwareUUID string `json:"hardware_uuid"`
	Hostname     string `json:"hostname"`
	OSVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
}

// EnrollResponse is what the agent receives. The HostToken is the only
// place the raw token bytes appear server-side; subsequent verification
// uses the SHA-256 digest stored in the DB.
//
// Initial policy fan-out happens through the command queue (a separate
// best-effort goroutine in the enroll handler), not through this
// response, so the agent's wire surface stays minimal.
type EnrollResponse struct {
	HostID     string    `json:"host_id"`
	HostToken  string    `json:"host_token"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// RotationTrigger describes who initiated a host-token rotation. Used by
// the audit row payload so reviewers can distinguish a routine
// scheduled rotation from a deliberate operator-driven one (incident
// response, suspected token leak). Stored as a string so adding new
// triggers (e.g. "scheduler" if a background sweep is added later) is a
// constant-time addition rather than a wire-shape break.
type RotationTrigger string

const (
	// RotationTriggerAuto is the verify-time trigger: an agent presented
	// a token whose host_token_issued_at + lifetime is in the past.
	RotationTriggerAuto RotationTrigger = "auto"
	// RotationTriggerOperator is the explicit operator-driven trigger
	// from POST /api/enrollments/{host_id}/rotate.
	RotationTriggerOperator RotationTrigger = "operator"
)

// RotateResult is the operator-visible outcome of a host-token rotation.
// The newly minted raw token is intentionally NOT in this struct: the
// agent receives it via the rotate_token command on its next poll, and
// surfacing it through the operator API would tempt copy-paste flows
// that bypass the command queue. PreviousTokenIDPrefix is the hex of
// the first 4 bytes of the rotated-out host_token_id, included on the
// operator's UI confirmation + the audit row so a reviewer can pivot
// from a rotation event to the verify request that triggered it
// (audit + access-log share the X-Request-ID / trace_id correlation).
//
// CommandID is the rotate_token command queued for the agent. *int64
// (not int64) so a rotation that committed in the DB but failed to
// queue the agent command is observably distinct on the wire: nil ->
// JSON omits command_id, telling the operator UI "rotation succeeded
// but the agent will only pick up the new token via re-enroll after
// the previous-token grace expires." A bare int64 zero would be
// indistinguishable from a successful queue at id 0 (auto-increment
// never returns 0, but a JSON consumer can't know that without
// reading server source).
type RotateResult struct {
	PreviousTokenIDPrefix string `json:"previous_token_id_prefix"`
	CommandID             *int64 `json:"command_id,omitempty"`
}

// Errors returned across the api boundary. Callers compare with errors.Is.
var (
	// ErrInvalidSecret is returned when the agent's enroll_secret doesn't
	// match the configured value. Mapped to 401 by the enroll handler.
	ErrInvalidSecret = errors.New("endpoint: invalid enroll secret")

	// ErrInvalidToken is returned when a presented bearer token does not
	// resolve to an active enrollment (unknown, revoked, or malformed).
	// Callers do not get to distinguish those cases; that would be an
	// oracle for token-still-active probing.
	ErrInvalidToken = errors.New("endpoint: invalid host token")

	// ErrInvalidHardwareUUID is returned when the agent presents an
	// unparseable hardware UUID. Mapped to 400.
	ErrInvalidHardwareUUID = errors.New("endpoint: invalid hardware uuid")

	// ErrInvalidEnrollRequest is returned when one or more required fields
	// of the EnrollRequest are blank (enroll_secret, hardware_uuid,
	// hostname, os_version, agent_version). Mapped to 400 by the HTTP
	// handler. A separate sentinel from ErrInvalidSecret so non-HTTP
	// callers (tests, future contexts) can distinguish "shape" from
	// "credential" without parsing free-form error strings.
	ErrInvalidEnrollRequest = errors.New("endpoint: invalid enroll request")

	// ErrNotFound is returned by Get / Revoke when the host_id has no
	// enrollment row.
	ErrNotFound = errors.New("endpoint: enrollment not found")
)

// CommandInserter is a closure type defined in endpoint/bootstrap
// (consumed by endpoint/internal/service via the call site
// `s.commands(ctx, hostID, ct, payload)`). cmd/main passes
// responseCtx.Service().Insert as a method value, which matches the
// closure shape; using a func type instead of a one-method interface
// lets endpoint and rules share the pattern without endpoint
// importing response/api.
