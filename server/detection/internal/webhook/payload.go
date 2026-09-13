// Package webhook holds the pure delivery logic for outbound alert webhooks (issue #496): the versioned payload envelope, the
// Standard Webhooks HMAC signature, and the SSRF egress guards. It has no persistence or HTTP-server dependencies so each piece is
// unit-testable in isolation; the detection store enqueues envelopes and the pipeline delivery worker signs and POSTs them.
package webhook

import (
	"encoding/json"
	"net/url"
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
	// EventTest is the event type of an operator-initiated test delivery. It is never enqueued from an alert; only the test-send path
	// emits it, so a receiver can recognize and ignore a connectivity probe.
	EventTest EventType = "webhook.test"
	// EventHealthEpisodeOpened is a host health episode opening: a fault in this product's own sensor that needs a person, such as a
	// capture provider its automatic repair could not restore (issue #778). It carries a health_episode body and no alert body.
	EventHealthEpisodeOpened EventType = "host.health_episode_opened"
)

// Envelope is the versioned JSON body POSTed to a destination. It is built once at enqueue and stored verbatim in the outbox, so the
// signature is computed over stable bytes and the payload reflects the alert at the instant the event fired rather than at send time.
//
// An envelope has exactly one subject. Alert is set for alert events and HealthEpisode for host health events, and each is omitted
// when it is not the subject. Alert stays in its original position and is a pointer only so a health event can leave it out: an
// alert envelope serializes to the same bytes it always did, which golden_test.go pins, so an existing receiver sees no change.
type Envelope struct {
	SchemaVersion   string             `json:"schema_version"`
	EventID         string             `json:"event_id"`
	EventType       EventType          `json:"event_type"`
	OccurredAt      time.Time          `json:"occurred_at"`
	DeliveryAttempt int                `json:"delivery_attempt"`
	Alert           *AlertBody         `json:"alert,omitempty"`
	HealthEpisode   *HealthEpisodeBody `json:"health_episode,omitempty"`
	Host            HostBody           `json:"host"`
	Process         *ProcessBody       `json:"process,omitempty"`
	Links           Links              `json:"links"`
}

// HealthEpisodeBody is the host health episode a health event describes. Detail is the fault's own machine-readable fields exactly as
// recorded, so a receiver branching on kind gets the provider, outcome, and attempt count as values instead of parsing a sentence.
// OpenedAt is when the fault began as observed ON THE HOST, not when this delivery was enqueued.
type HealthEpisodeBody struct {
	ID          int64           `json:"id"`
	Kind        string          `json:"kind"`
	Component   string          `json:"component"`
	Subject     string          `json:"subject,omitempty"`
	Severity    string          `json:"severity"`
	Title       string          `json:"title"`
	Description string          `json:"description,omitempty"`
	Detail      json.RawMessage `json:"detail,omitempty"`
	OpenedAt    time.Time       `json:"opened_at"`
}

// AlertBody is the alert projection carried in the envelope. PreviousStatus is populated only for status-change events.
type AlertBody struct {
	ID             int64  `json:"id"`
	Status         string `json:"status"`
	PreviousStatus string `json:"previous_status,omitempty"`
	Severity       string `json:"severity"`
	Source         string `json:"source"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	RuleID         string `json:"rule_id"`
	// Origin credits the author of the rule that fired, mirroring detection/api.Alert.Origin. Carried into the delivery because a
	// receiver that renders our alerts is a surface displaying a match, and the vendored corpus's licence attaches the same
	// attribution requirement there as in our own UI. Additive: SchemaVersion is unchanged, since a consumer that does not read
	// the field is unaffected by its presence.
	//
	// Omitted in two cases, neither of them a fault: an alert raised before migration 00012 added the column, and an
	// application-control block, whose rule id is the operator's own policy rather than a detection with an author.
	Origin     string     `json:"origin,omitempty"`
	Techniques []string   `json:"techniques,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
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
		Alert: &AlertBody{
			ID:             p.Alert.ID,
			Status:         string(p.Alert.Status),
			PreviousStatus: p.PreviousStatus,
			Severity:       p.Alert.Severity,
			Source:         p.Alert.Source,
			Title:          p.Alert.Title,
			Description:    p.Alert.Description,
			Origin:         p.Alert.Origin,
			RuleID:         p.Alert.RuleID,
			Techniques:     []string(p.Alert.Techniques),
			CreatedAt:      p.Alert.CreatedAt,
			UpdatedAt:      p.Alert.UpdatedAt,
		},
		Host:  HostBody{ID: p.Alert.HostID},
		Links: Links{Console: consoleLink(p.ConsoleBaseURL, p.Alert.ID)},
	}
	// Copy ResolvedAt by value rather than aliasing the caller's pointer, so a later mutation of the source alert cannot reach into
	// an already-built envelope.
	if p.Alert.ResolvedAt != nil {
		resolved := *p.Alert.ResolvedAt
		e.Alert.ResolvedAt = &resolved
	}
	if p.Alert.ProcessID != 0 {
		e.Process = &ProcessBody{PID: p.Alert.ProcessID}
	}
	return e
}

// HealthBuildParams are the inputs for one health-episode delivery envelope.
type HealthBuildParams struct {
	EventID        string
	Attempt        int
	HostID         string
	Episode        HealthEpisodeBody
	ConsoleBaseURL string
}

// BuildHealthEpisode assembles the envelope for a host health episode opening. Like Build it performs no I/O, so the same inputs
// always produce the same bytes and the signature is stable across delivery attempts.
//
// OccurredAt is the episode's own opening instant rather than the enqueue time, for the reason the episode carries a host-observed
// clock at all: a receiver computing how long a host has been blind should measure from when it went blind, not from when a queue
// got round to telling them.
func BuildHealthEpisode(p HealthBuildParams) Envelope {
	episode := p.Episode
	// Copied rather than aliased, so a later mutation of the caller's detail buffer cannot reach into an envelope already built.
	if len(episode.Detail) > 0 {
		episode.Detail = append(json.RawMessage(nil), episode.Detail...)
	}
	return Envelope{
		SchemaVersion:   SchemaVersion,
		EventID:         p.EventID,
		EventType:       EventHealthEpisodeOpened,
		OccurredAt:      episode.OpenedAt,
		DeliveryAttempt: p.Attempt,
		HealthEpisode:   &episode,
		Host:            HostBody{ID: p.HostID},
		Links:           Links{Console: hostConsoleLink(p.ConsoleBaseURL, p.HostID)},
	}
}

// hostConsoleLink is the operator-facing host URL, the destination a health event pivots to: the fault is about the host's sensor,
// not about any one alert on it.
func hostConsoleLink(base, hostID string) string {
	return joinConsoleBase(base, "/ui/hosts/"+url.PathEscape(hostID))
}

// consoleLink derives the operator-facing alert URL from the deployment external URL. It trims a trailing slash so the path is not
// doubled, and returns just the path when no base URL is configured so the receiver still gets a usable relative link.
func consoleLink(base string, alertID int64) string {
	return joinConsoleBase(base, "/ui/alerts?id="+strconv.FormatInt(alertID, 10))
}

// joinConsoleBase prefixes path with the deployment base URL, trimming a trailing slash so the path is not doubled, and returns the bare
// path when no base is configured so the receiver still gets a usable relative link. Shared by both link kinds so they cannot drift in
// how a base URL is normalized.
func joinConsoleBase(base, path string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(base), "/")
	if trimmed == "" {
		return path
	}
	return trimmed + path
}
