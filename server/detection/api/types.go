package api

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/sqlhelpers"
)

// NullRawJSON is the canonical nullable JSON column scanner. The
// authoritative type lives in server/sqlhelpers; detection/api keeps
// the public name so existing callers (and the rules.api re-export)
// stay byte-identical with the pre-phase-6 import path.
type NullRawJSON = sqlhelpers.NullRawJSON

// Compile-time pin that the scanner / valuer / json contracts the rest
// of detection relies on are still satisfied through the alias.
var (
	_ interface {
		Scan(any) error
	} = (*NullRawJSON)(nil)
	_ driver.Valuer  = NullRawJSON(nil)
	_ json.Marshaler = NullRawJSON(nil)
	_ interface {
		UnmarshalJSON([]byte) error
	} = (*NullRawJSON)(nil)
)

// Event mirrors a row in the events table. The agent posts these to
// /api/events; the engine evaluates rules over batches of these.
//
// Wire shape MUST stay byte-identical with what earlier server
// versions produced: agents in the field decode server-emitted Events
// for /api/commands result payloads.
type Event struct {
	EventID      string          `db:"event_id" json:"event_id"`
	HostID       string          `db:"host_id" json:"host_id"`
	TimestampNs  int64           `db:"timestamp_ns" json:"timestamp_ns"`
	IngestedAtNs int64           `db:"ingested_at_ns" json:"ingested_at_ns,omitempty"`
	EventType    string          `db:"event_type" json:"event_type"`
	Payload      json.RawMessage `db:"payload" json:"payload"`
}

// Process represents a materialized process record built from
// fork/exec/exit events. Wire shape preserved from server/store.Process.
type Process struct {
	ID               int64       `db:"id" json:"id"`
	HostID           string      `db:"host_id" json:"host_id"`
	PID              int         `db:"pid" json:"pid"`
	PPID             int         `db:"ppid" json:"ppid"`
	Path             string      `db:"path" json:"path"`
	Args             NullRawJSON `db:"args" json:"args,omitempty"`
	UID              *int        `db:"uid" json:"uid,omitempty"`
	GID              *int        `db:"gid" json:"gid,omitempty"`
	CodeSigning      NullRawJSON `db:"code_signing" json:"code_signing,omitempty"`
	SHA256           *string     `db:"sha256" json:"sha256,omitempty"`
	ForkTimeNs       int64       `db:"fork_time_ns" json:"fork_time_ns"`
	ForkIngestedAtNs *int64      `db:"fork_ingested_at_ns" json:"fork_ingested_at_ns,omitempty"`
	ExecTimeNs       *int64      `db:"exec_time_ns" json:"exec_time_ns,omitempty"`
	ExitTimeNs       *int64      `db:"exit_time_ns" json:"exit_time_ns,omitempty"`
	ExitIngestedAtNs *int64      `db:"exit_ingested_at_ns" json:"exit_ingested_at_ns,omitempty"`
	ExitReason       *string     `db:"exit_reason" json:"exit_reason,omitempty"`
	ExitCode         *int        `db:"exit_code" json:"exit_code,omitempty"`
	// PreviousExecID points at the row representing the prior generation
	// in a same-PID re-exec chain (issue #10). The first exec after a
	// fork has PreviousExecID == nil; that's the chain root.
	PreviousExecID *int64 `db:"previous_exec_id" json:"previous_exec_id,omitempty"`
}

// ExitReason values for Process.ExitReason.
const (
	ExitReasonEvent             = "event"              // normal: populated from an observed ES exit event
	ExitReasonTTLReconciliation = "ttl_reconciliation" // synthesized: process stayed running past the TTL; server forced a gray
	ExitReasonPIDReuse          = "pid_reuse"          // synthesized: incoming fork on the same PID forced closure of the prior row
	ExitReasonReExec            = "reexec"             // synthesized: superseded by a new execve() on the same PID (issue #10)
	ExitReasonHostReconciled    = "host_reconciled"    // synthesized: agent's kill(pid,0) confirmed the PID is gone (issue #6)
)

// HostSummary is the lightweight per-host activity row the operator
// list endpoint returns. Distinct from Host so future extensions
// (alert counts, status pill) can land without touching Host's wire
// shape.
type HostSummary struct {
	HostID     string `db:"host_id" json:"host_id"`
	EventCount int64  `db:"event_count" json:"event_count"`
	LastSeenNs int64  `db:"last_seen_ns" json:"last_seen_ns"`
}

// Host is the operator-visible row from the hosts summary table.
// Mirrors HostSummary but adds updated_at; both are kept distinct
// because the operator list endpoint historically returned the
// HostSummary shape and the UI snapshots it.
type Host struct {
	HostID     string    `db:"host_id" json:"host_id"`
	EventCount int64     `db:"event_count" json:"event_count"`
	LastSeenNs int64     `db:"last_seen_ns" json:"last_seen_ns"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
}

// JSONStringSlice is a []string persisted as a JSON array in a MySQL
// JSON column. NULL + SQL empty-string round-trip to a nil slice;
// the JSON marshal path keeps the field omitted when empty. Used by
// Alert.Techniques (the MITRE ATT&CK technique IDs).
type JSONStringSlice []string

func (s *JSONStringSlice) Scan(value any) error {
	if value == nil {
		*s = nil
		return nil
	}
	var b []byte
	switch v := value.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return fmt.Errorf("JSONStringSlice.Scan: unsupported type %T", value)
	}
	if len(b) == 0 {
		*s = nil
		return nil
	}
	return json.Unmarshal(b, s)
}

func (s JSONStringSlice) Value() (driver.Value, error) {
	if len(s) == 0 {
		return nil, nil
	}
	return json.Marshal(s)
}

// Alert is a persisted detection finding.
type Alert struct {
	ID          int64           `db:"id" json:"id"`
	HostID      string          `db:"host_id" json:"host_id"`
	RuleID      string          `db:"rule_id" json:"rule_id"`
	Source      string          `db:"source" json:"source"`
	Severity    string          `db:"severity" json:"severity"`
	Title       string          `db:"title" json:"title"`
	Description string          `db:"description" json:"description"`
	ProcessID   int64           `db:"process_id" json:"process_id"`
	Techniques  JSONStringSlice `db:"techniques" json:"techniques,omitempty"`
	Status      AlertStatus     `db:"status" json:"status"`
	CreatedAt   time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time       `db:"updated_at" json:"updated_at"`
	ResolvedAt  *time.Time      `db:"resolved_at" json:"resolved_at,omitempty"`
	UpdatedBy   *int64          `db:"updated_by" json:"updated_by,omitempty"`
}

// AlertSource records what subsystem emitted an alert. The schema's
// `source` ENUM mirrors this set. Including source in the alert dedup
// key prevents a catalog rule and an application-control rule that
// happen to share an identifier value from collapsing into one alert
// row (see server-detection-rules-engine delta spec).
const (
	// AlertSourceDetection is the source for findings produced by
	// catalog rules. The default for engine.persistFinding when a
	// Finding leaves the field blank, since every catalog rule was
	// "detection" before the source column was introduced.
	AlertSourceDetection = "detection"
	// AlertSourceApplicationControl is the source for alerts
	// produced by an application_control_block ingest event.
	AlertSourceApplicationControl = "application_control"
)

// AlertStatus enumerates the operator-driven alert lifecycle.
// Schema-level ENUM('open','acknowledged','resolved'); the UI
// presents these labels.
type AlertStatus string

const (
	AlertStatusOpen         AlertStatus = "open"
	AlertStatusAcknowledged AlertStatus = "acknowledged"
	AlertStatusResolved     AlertStatus = "resolved"
)

// Severity levels aligned with industry standards (CrowdStrike, MITRE).
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Finding is a per-rule positive output, persisted by the engine
// into the alerts table. Canonical definition; rules/api re-exports
// it as a type alias so catalog rule files implement
// rulesapi.Rule.Evaluate without importing detection/api directly
// (see arch-go.yml §api-purity for the alias rationale).
//
// Source is optional: when blank, engine.persistFinding defaults it
// to AlertSourceDetection so existing catalog rules keep working
// unchanged. The application-control block rule explicitly sets
// AlertSourceApplicationControl.
type Finding struct {
	HostID      string
	RuleID      string
	Source      string
	Severity    string
	Title       string
	Description string
	ProcessID   int64
	EventIDs    []string
	Techniques  []string
}

// TimeRange is the [from, to] nanosecond window every graph query
// takes. The canonical type lives in server/httpserver because the
// concept is generic and shared across every operator endpoint that
// parses ?from=&to= query parameters; detection/api keeps the public
// name via alias so existing callers (and the rules.api re-export)
// stay byte-identical.
type TimeRange = httpserver.TimeRange

// AlertFilter is the optional scope an operator passes to ListAlerts.
// Mirrors the existing GET /api/alerts query params so the wire
// shape is preserved; Since / Until / Offset are deferred follow-ups
// (filed alongside the time-range and pagination work).
type AlertFilter struct {
	HostID    string
	Status    AlertStatus
	Severity  string
	Source    string
	ProcessID int64
	Limit     int
}

// ProcessNode is the tree shape the UI's process-tree view renders.
// Wire shape preserved from server/graph.ProcessNode.
type ProcessNode struct {
	Process
	Children           []ProcessNode `json:"children,omitempty"`
	NetworkConnections []Event       `json:"network_connections,omitempty"`
	DNSQueries         []Event       `json:"dns_queries,omitempty"`
}

// ProcessDetail is the wire shape of GET /api/hosts/{id}/processes/{pid}.
// Mirrors server/graph.ProcessDetail.
type ProcessDetail struct {
	Process            Process `json:"process"`
	NetworkConnections []Event `json:"network_connections"`
	DNSQueries         []Event `json:"dns_queries"`
	// ReExecChain is the list of prior exec generations on the same
	// PID (issue #10), oldest-first. Empty for processes that only
	// exec'd once after fork. The UI renders this as a visual chain
	// (python -> sh -> bash -> current) so analysts see the full
	// exec sequence instead of just the final path.
	ReExecChain []Process `json:"re_exec_chain,omitempty"`
}

// Errors returned across the api boundary. Callers compare with
// errors.Is.
var (
	// ErrAlertNotFound is returned by GetAlert / UpdateAlertStatus
	// when the id doesn't exist.
	ErrAlertNotFound = errors.New("detection: alert not found")

	// ErrInvalidAlertTransition is returned when UpdateAlertStatus is
	// called with a status that doesn't follow from the row's current
	// status (e.g. resolved -> open). Mapped to 400 by the operator
	// handler.
	ErrInvalidAlertTransition = errors.New("detection: invalid alert status transition")

	// ErrInvalidUserUpdater is returned when UpdateAlertStatus is
	// called with a user_id that the identity context does not
	// recognise. Replaces the FK-level rejection that fk_alerts_updated_by
	// enforced in the pre-bounded-context schema.
	ErrInvalidUserUpdater = errors.New("detection: updated_by user does not exist")

	// ErrHostNotFound is returned by host-keyed reads when the host
	// has no rows.
	ErrHostNotFound = errors.New("detection: host not found")

	// ErrProcessNotFound is returned by process-keyed reads.
	ErrProcessNotFound = errors.New("detection: process not found")
)

// IsValidationError reports whether err is one of the public
// 4xx-mapped validation sentinels.
func IsValidationError(err error) bool {
	return errors.Is(err, ErrInvalidAlertTransition) ||
		errors.Is(err, ErrInvalidUserUpdater)
}
