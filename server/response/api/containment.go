package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// CommandTypeSetNetworkContainment is the command that delivers a host's containment state to its agent, which hands it to the network
// extension and completes the command once the extension applied it (#948).
const CommandTypeSetNetworkContainment = "set_network_containment"

// SetNetworkContainmentPayload is the set_network_containment payload. Version orders a host's states; Epoch is the state's change time
// in microseconds, so a host still orders states correctly after a database restore sends versions backwards.
type SetNetworkContainmentPayload struct {
	Version   int64 `json:"version"`
	Epoch     int64 `json:"epoch"`
	Contained bool  `json:"contained"`
}

// ContainmentState is a host's desired containment and how its delivery stands.
type ContainmentState struct {
	HostID    string     `json:"host_id"`
	Contained bool       `json:"contained"`
	Version   int64      `json:"version"`
	Epoch     int64      `json:"epoch"`
	Reason    string     `json:"reason,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// Delivery is the host's latest set_network_containment command. Nil when none was ever queued, and for a host with no containment
	// state, whose version is 0, whatever commands were queued for it by other means.
	Delivery *ContainmentDelivery `json:"delivery,omitempty"`
}

// ContainmentDelivery is the latest set_network_containment command for a host.
type ContainmentDelivery struct {
	CommandID int64           `json:"command_id"`
	Status    Status          `json:"status"`
	Result    json.RawMessage `json:"result,omitempty"`
	// Current says whether the command carries the host's current version and epoch. A completed command that is not current
	// confirms an earlier state, not this one.
	Current bool `json:"current"`
}

// ContainmentChange is the result of asking for a containment state: the state after the request, whether it changed, and the id of
// the command queued for it, which is zero only when nothing changed. A change and its command are recorded in one transaction, so a
// change that is reported as made has a command (issue #1073).
type ContainmentChange struct {
	State     ContainmentState `json:"state"`
	Changed   bool             `json:"changed"`
	CommandID int64            `json:"command_id,omitempty"`
}

// ErrContainmentReasonRequired is returned for a containment change without a reason.
var ErrContainmentReasonRequired = errors.New("containment: reason is required")

// ErrContainmentHostNotFound is returned for a containment change on a host with no active enrollment.
var ErrContainmentHostNotFound = errors.New("containment: host has no active enrollment")

// ErrContainmentReasonTooLong is returned for a containment change whose reason is longer than MaxContainmentReasonLength characters.
var ErrContainmentReasonTooLong = errors.New("containment: reason is too long")

// MaxContainmentReasonLength is the longest reason a containment change records, in characters.
const MaxContainmentReasonLength = 1024

// HostEnrollment is an active enrollment's host and the time it last enrolled, on the database clock.
type HostEnrollment struct {
	HostID     string
	EnrolledAt time.Time
}

// ActiveEnrollmentLister lists the active enrollments. cmd/main wires it from the endpoint context.
type ActiveEnrollmentLister func(ctx context.Context) ([]HostEnrollment, error)

// HostEnrolledChecker reports whether a host has an active enrollment. cmd/main wires it from the endpoint context.
type HostEnrolledChecker func(ctx context.Context, hostID string) (bool, error)
