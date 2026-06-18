package api

import (
	"encoding/json"
	"errors"
	"time"
)

// Command mirrors a row in the commands table. Field tags preserve
// today's wire shape so the agent's commander + operator UI see
// byte-identical JSON.
//
// Status moves through pending -> acked -> (completed | failed).
// pending -> failed is also legal (immediate rejection by the agent).
// Any other transition is rejected by Service.UpdateStatus with
// ErrInvalidStatusTransition.
type Command struct {
	ID          int64           `json:"id"`
	HostID      string          `json:"host_id"`
	CommandType string          `json:"command_type"`
	Payload     json.RawMessage `json:"payload"`
	Status      Status          `json:"status"`
	Result      json.RawMessage `json:"result,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	AckedAt     *time.Time      `json:"acked_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
}

// Status is the lifecycle state of a command. The string values match the MySQL ENUM in bootstrap/schema.go and the agent commander's
// wire contract. Adding a new state means updating the agent + the ENUM at the same time.
type Status string

const (
	StatusPending   Status = "pending"
	StatusAcked     Status = "acked"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// CommandTypeKillProcess is the well-known type the agent's commander dispatches to its kill-process handler. Other command types
// live in their owning contexts (notably rules/api.CommandTypeSetBlocklist). Operator POST /api/commands accepts any non-empty string
// today; future hardening can tighten this to a typed enum.
const CommandTypeKillProcess = "kill_process"

// InsertRequest groups the fields the operator + agent handlers decode off the wire when issuing a command. Service.Insert takes
// the fields directly (hostID, commandType, payload) rather than this struct. The struct is exported as a convenience for non-HTTP
// callers (admin issuance via automation, future job runners) that prefer to construct one value and forward its fields.
type InsertRequest struct {
	HostID      string
	CommandType string
	Payload     json.RawMessage
}

// UpdateStatusRequest is the payload Service.UpdateStatus accepts.
// The lifecycle matrix is:
//
//	pending -> acked              (agent picked it up; Result ignored)
//	pending -> failed             (agent immediately rejected; Result optional)
//	acked   -> completed          (agent applied successfully; Result optional)
//	acked   -> failed             (agent applied with errors; Result optional)
//
// Other transitions are rejected with ErrInvalidStatusTransition.
// Terminal states (completed, failed) are immutable.
type UpdateStatusRequest struct {
	// HostID is the pinned host_id from the agent's host-token. The service rejects updates whose stored row belongs to a different host
	// so a valid token for host A cannot ack host B's commands.
	HostID string
	ID     int64
	Status Status
	Result json.RawMessage
}

// Errors returned across the api boundary. Callers compare with
// errors.Is.
var (
	// ErrCommandNotFound is returned by Get / UpdateStatus when the id doesn't exist OR (on UpdateStatus) the row exists but belongs
	// to a different host than the pinned host_id. The two cases are intentionally collapsed so a malicious agent can't probe other hosts'
	// command_ids.
	ErrCommandNotFound = errors.New("response: command not found")

	// ErrInvalidStatusTransition is returned when UpdateStatus is called with a status that doesn't follow from the row's current status
	// (e.g. pending -> completed without an acked step). Mapped to 400 by the agent handler.
	ErrInvalidStatusTransition = errors.New("response: invalid status transition")

	// ErrInvalidInsertRequest is returned for body-shape problems on Service.Insert: missing HostID, missing CommandType, or empty
	// Payload. Mapped to 400 by the operator handler.
	ErrInvalidInsertRequest = errors.New("response: invalid insert request")
)

// IsValidationError reports whether err is one of the public
// 4xx-mapped validation sentinels.
func IsValidationError(err error) bool {
	return errors.Is(err, ErrInvalidInsertRequest) ||
		errors.Is(err, ErrInvalidStatusTransition)
}
