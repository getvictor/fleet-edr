// Package webhook holds the pure delivery logic for outbound alert webhooks (issue #496): the versioned payload envelope, the
// Standard Webhooks HMAC signature, and the SSRF egress guards. It has no persistence or HTTP-server dependencies so each piece is
// unit-testable in isolation; the detection store enqueues envelopes and the pipeline delivery worker signs and POSTs them.
package webhook

import (
	"strconv"
	"strings"
	"time"

	detapi "github.com/fleetdm/edr/server/detection/api"
)

// SchemaVersion is the payload envelope version. Receivers branch on it; bump it only on a breaking wire change.
const SchemaVersion = "1.0"

// EventType is the alert lifecycle event that triggered a delivery.
type EventType string

const (
	EventAlertCreated       EventType = "alert.created"
	EventAlertStatusChanged EventType = "alert.status_changed"
)

// Envelope is the versioned JSON body POSTed to a destination. It is built once at enqueue and stored verbatim in the outbox, so the
// signature is computed over stable bytes and the payload reflects the alert at the instant the event fired rather than at send time.
type Envelope struct {
	SchemaVersion   string       `json:"schema_version"`
	EventID         string       `json:"event_id"`
	EventType       EventType    `json:"event_type"`
	OccurredAt      time.Time    `json:"occurred_at"`
	DeliveryAttempt int          `json:"delivery_attempt"`
	Alert           AlertBody    `json:"alert"`
	Host            HostBody     `json:"host"`
	Process         *ProcessBody `json:"process,omitempty"`
	Links           Links        `json:"links"`
}

// AlertBody is the alert projection carried in the envelope. PreviousStatus is populated only for status-change events.
type AlertBody struct {
	ID             int64      `json:"id"`
	Status         string     `json:"status"`
	PreviousStatus string     `json:"previous_status,omitempty"`
	Severity       string     `json:"severity"`
	Source         string     `json:"source"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	RuleID         string     `json:"rule_id"`
	Techniques     []string   `json:"techniques,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
}

// HostBody is the triggering host context. Only the stable host id is carried; richer host enrichment is a documented follow-up.
type HostBody struct {
	ID string `json:"id"`
}

// ProcessBody is the triggering process context, omitted for process-less alerts (process id 0).
type ProcessBody struct {
	PID int64 `json:"pid"`
}

// Links carries deep links back into the console so a receiver can pivot to the full alert without embedding console state.
type Links struct {
	Console string `json:"console"`
}

// BuildParams are the inputs for one delivery envelope.
type BuildParams struct {
	EventID        string
	EventType      EventType
	OccurredAt     time.Time
	Attempt        int
	Alert          detapi.Alert
	PreviousStatus string // set only for status-change events
	ConsoleBaseURL string // deployment external URL; a trailing slash is tolerated
}

// Build assembles the envelope from an alert and event metadata. It performs no I/O: every field comes from the passed-in alert or
// params, so the same inputs always produce the same bytes (a prerequisite for a stable signature across delivery attempts).
func Build(p BuildParams) Envelope {
	e := Envelope{
		SchemaVersion:   SchemaVersion,
		EventID:         p.EventID,
		EventType:       p.EventType,
		OccurredAt:      p.OccurredAt,
		DeliveryAttempt: p.Attempt,
		Alert: AlertBody{
			ID:             p.Alert.ID,
			Status:         string(p.Alert.Status),
			PreviousStatus: p.PreviousStatus,
			Severity:       p.Alert.Severity,
			Source:         p.Alert.Source,
			Title:          p.Alert.Title,
			Description:    p.Alert.Description,
			RuleID:         p.Alert.RuleID,
			Techniques:     []string(p.Alert.Techniques),
			CreatedAt:      p.Alert.CreatedAt,
			UpdatedAt:      p.Alert.UpdatedAt,
			ResolvedAt:     p.Alert.ResolvedAt,
		},
		Host:  HostBody{ID: p.Alert.HostID},
		Links: Links{Console: consoleLink(p.ConsoleBaseURL, p.Alert.ID)},
	}
	if p.Alert.ProcessID != 0 {
		e.Process = &ProcessBody{PID: p.Alert.ProcessID}
	}
	return e
}

// consoleLink derives the operator-facing alert URL from the deployment external URL. It trims a trailing slash so the path is not
// doubled, and returns just the path when no base URL is configured so the receiver still gets a usable relative link.
func consoleLink(base string, alertID int64) string {
	path := "/ui/alerts?id=" + strconv.FormatInt(alertID, 10)
	trimmed := strings.TrimRight(strings.TrimSpace(base), "/")
	if trimmed == "" {
		return path
	}
	return trimmed + path
}
