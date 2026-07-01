package api

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/sqlhelpers"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// NullRawJSON is the canonical nullable JSON column scanner. The authoritative type lives in server/sqlhelpers; detection/api keeps
// the public name so existing callers (and the rules.api re-export) stay byte-identical with the pre-phase-6 import path.
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

// Event is the raw endpoint telemetry envelope. Its canonical definition moved to the visibility bounded context (ADR-0015), which
// owns ingestion and the event store; detection/api keeps the name as a type alias so existing callers (and the rules.api re-export)
// stay byte-identical while the dependency points the right way (detection -> visibility). The wire shape and db tags live on
// visibilityapi.Event.
type Event = visibilityapi.Event

// Process represents a materialized process record built from
// fork/exec/exit events. Wire shape preserved from server/store.Process.
type Process struct {
	ID          int64       `db:"id" json:"id"`
	HostID      string      `db:"host_id" json:"host_id"`
	PID         int         `db:"pid" json:"pid"`
	PPID        int         `db:"ppid" json:"ppid"`
	Path        string      `db:"path" json:"path"`
	Args        NullRawJSON `db:"args" json:"args,omitempty"`
	UID         *int        `db:"uid" json:"uid,omitempty"`
	GID         *int        `db:"gid" json:"gid,omitempty"`
	CodeSigning NullRawJSON `db:"code_signing" json:"code_signing,omitempty"`
	SHA256      *string     `db:"sha256" json:"sha256,omitempty"`
	// CDHash is the 40-hex code-directory hash (sha1 of the CDDirectory blob) the agent extracts on Hardened-Runtime processes
	// (issue #68 / PR #185). NULL for non-HR binaries since the ESF target tuple lacks a meaningful cdhash for them. Persisted
	// alongside sha256 so incident response can correlate by either hash and so app-control's CDHASH rule matches replay nicely.
	CDHash *string `db:"cdhash" json:"cdhash,omitempty"`
	// PIDVersion is the kernel PID generation (audit_token_to_pidversion) of this process, when the originating exec/fork event
	// carried it. It pins process identity across PID reuse: a flow tagged with (host, pid, pidversion) correlates to the exact
	// generation regardless of fork/exit timing. NULL for legacy-agent rows and for rows whose audit token was unavailable; a
	// present 0 is a legitimate generation, so absence is NULL rather than a 0 sentinel (issue #403).
	PIDVersion       *uint32 `db:"pidversion" json:"pidversion,omitempty"`
	ForkTimeNs       int64   `db:"fork_time_ns" json:"fork_time_ns"`
	ForkIngestedAtNs *int64  `db:"fork_ingested_at_ns" json:"fork_ingested_at_ns,omitempty"`
	ExecTimeNs       *int64  `db:"exec_time_ns" json:"exec_time_ns,omitempty"`
	ExitTimeNs       *int64  `db:"exit_time_ns" json:"exit_time_ns,omitempty"`
	ExitIngestedAtNs *int64  `db:"exit_ingested_at_ns" json:"exit_ingested_at_ns,omitempty"`
	ExitReason       *string `db:"exit_reason" json:"exit_reason,omitempty"`
	ExitCode         *int    `db:"exit_code" json:"exit_code,omitempty"`
	// PreviousExecID points at the row representing the prior generation in a same-PID re-exec chain (issue #10). The first exec after a
	// fork has PreviousExecID == nil; that's the chain root.
	PreviousExecID *int64 `db:"previous_exec_id" json:"previous_exec_id,omitempty"`
	// IsSnapshot is true for rows materialised from the extension's startup baseline pass (issue #11). The TTL reconciler exempts these
	// from the issue #6 force-exit unless they're stale relative to last_seen_ns.
	IsSnapshot bool `db:"is_snapshot" json:"is_snapshot,omitempty"`
	// LastSeenNs is the most recent agent-side liveness signal for a snapshot row (issue #173). NULL for non-snapshot rows. The TTL
	// reconciler uses COALESCE(last_seen_ns, fork_time_ns) so non-snapshot rows fall back to existing #6 behaviour.
	LastSeenNs *int64 `db:"last_seen_ns" json:"last_seen_ns,omitempty"`
}

// ExitReason values for Process.ExitReason.
const (
	ExitReasonEvent             = "event"              // normal: populated from an observed ES exit event
	ExitReasonTTLReconciliation = "ttl_reconciliation" // synthesized: process stayed running past the TTL; server forced a gray
	ExitReasonPIDReuse          = "pid_reuse"          // synthesized: incoming fork on the same PID forced closure of the prior row
	ExitReasonReExec            = "reexec"             // synthesized: superseded by a new execve() on the same PID (issue #10)
	ExitReasonHostReconciled    = "host_reconciled"    // synthesized: agent's kill(pid,0) confirmed the PID is gone (issue #6)
)

// HostSummary is the lightweight per-host activity row the operator list endpoint returns. Distinct from Host so future extensions
// (alert counts, status pill) can land without touching Host's wire shape. Hostname and OSVersion are sourced from the endpoint
// context's enrollments table (LEFT JOIN in ListHosts) and are empty for a host that has sent events but carries no enrollment row.
type HostSummary struct {
	HostID     string `db:"host_id" json:"host_id"`
	Hostname   string `db:"hostname" json:"hostname"`
	OSVersion  string `db:"os_version" json:"os_version"`
	EventCount int64  `db:"event_count" json:"event_count"`
	LastSeenNs int64  `db:"last_seen_ns" json:"last_seen_ns"`
	// OverallStatus is the server-computed agent-health rollup for the host (issue #359), sourced from the endpoint context's host_health
	// table (LEFT JOIN in ListHosts) and COALESCEd to HostHealthUnknown for a host that has never posted a status snapshot. It is the
	// Hosts-list badge signal, distinct from the online/offline pill the UI derives from LastSeenNs.
	OverallStatus string `db:"overall_status" json:"overall_status"`
}

// HostHealthUnknown is the overall-status value for a host with no recorded status snapshot: the agent has never checked in health, so
// the server knows nothing rather than asserting healthy. Matches the endpoint context's HealthUnknown spelling across the shared DB.
const HostHealthUnknown = "unknown"

// HostHealth is the operator-facing per-host agent-health detail served at GET /api/hosts/{host_id}/health. OverallStatus is the
// server-computed rollup; ReportedAtNs is the agent-stamped snapshot time; Components is the full ComponentHealth list exactly as the
// agent sent it, passed through as raw JSON so a new component type needs no server change. A host with no snapshot yields
// OverallStatus HostHealthUnknown and null Components.
type HostHealth struct {
	OverallStatus string      `db:"overall_status" json:"overall_status"`
	ReportedAtNs  int64       `db:"reported_at_ns" json:"reported_at_ns"`
	Components    NullRawJSON `db:"components" json:"components"`
}

// Host is the operator-visible row from the hosts summary table. Mirrors HostSummary but adds updated_at; both are kept distinct
// because the operator list endpoint historically returned the HostSummary shape and the UI snapshots it.
type Host struct {
	HostID     string    `db:"host_id" json:"host_id"`
	EventCount int64     `db:"event_count" json:"event_count"`
	LastSeenNs int64     `db:"last_seen_ns" json:"last_seen_ns"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
}

// JSONStringSlice is a []string persisted as a JSON array in a MySQL JSON column. NULL + SQL empty-string round-trip to a nil slice;
// the JSON marshal path keeps the field omitted when empty. Used by Alert.Techniques (the MITRE ATT&CK technique IDs).
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
	ID          int64  `db:"id" json:"id"`
	HostID      string `db:"host_id" json:"host_id"`
	RuleID      string `db:"rule_id" json:"rule_id"`
	Source      string `db:"source" json:"source"`
	Severity    string `db:"severity" json:"severity"`
	Title       string `db:"title" json:"title"`
	Description string `db:"description" json:"description"`
	// ProcessID is the enrichment link to processes(id); 0 for process-less alerts (e.g. BTM-registration persistence,
	// where the attacker has no live process). Reads COALESCE the nullable column back to 0.
	ProcessID int64 `db:"process_id" json:"process_id"`
	// Subject is the internal dedup identity (see schema.go); not exposed on the API. A blank Subject in a hand-built
	// Alert is defaulted to the ProcessID string by InsertAlert.
	Subject    string          `db:"subject" json:"-"`
	Techniques JSONStringSlice `db:"techniques" json:"techniques,omitempty"`
	Status     AlertStatus     `db:"status" json:"status"`
	CreatedAt  time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time       `db:"updated_at" json:"updated_at"`
	ResolvedAt *time.Time      `db:"resolved_at" json:"resolved_at,omitempty"`
	UpdatedBy  *string         `db:"updated_by" json:"updated_by,omitempty"`
}

// AlertSource records what subsystem emitted an alert. The schema's `source` ENUM mirrors this set. Including source in the alert
// dedup key prevents a catalog rule and an application-control rule that happen to share an identifier value from collapsing into one
// alert row (see server-detection-rules-engine delta spec).
const (
	// AlertSourceDetection is the source for findings produced by catalog rules. The default for engine.persistFinding when a Finding
	// leaves the field blank, since every catalog rule was "detection" before the source column was introduced.
	AlertSourceDetection = "detection"
	// AlertSourceApplicationControl is the source for alerts
	// produced by an application_control_block ingest event.
	AlertSourceApplicationControl = "application_control"
)

// AlertStatus enumerates the operator-driven alert lifecycle. Schema-level ENUM('open','acknowledged','resolved'); the UI presents
// these labels.
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
	// Subject overrides the dedup identity. Leave blank for process-backed findings: the engine defaults it to the
	// ProcessID, preserving the historical (source, host_id, rule_id, process_id) dedup. A process-less finding (e.g. BTM
	// persistence, ProcessID == 0) MUST set a stable, namespaced Subject (e.g. "launchdaemon:<plist>") so distinct items
	// produce distinct alerts rather than colliding on process_id 0.
	Subject    string
	EventIDs   []string
	Techniques []string
}

// TimeRange is the [from, to] nanosecond window every graph query takes. The canonical type lives in server/httpserver because the
// concept is generic and shared across every operator endpoint that parses ?from=&to= query parameters; detection/api keeps the public
// name via alias so existing callers (and the rules.api re-export) stay byte-identical.
type TimeRange = httpserver.TimeRange

// AlertFilter is the optional scope an operator passes to ListAlerts. Mirrors the existing GET /api/alerts query params so the wire
// shape is preserved; Since / Until / Offset are deferred follow-ups (filed alongside the time-range and pagination work).
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
	// ReExecChain is the list of prior exec generations on the same PID (issue #10), oldest-first. Empty for processes that only exec'd
	// once after fork. The UI renders this as a visual chain (python -> sh -> bash -> current) so analysts see the full exec sequence
	// instead of just the final path.
	ReExecChain []Process `json:"re_exec_chain,omitempty"`
}

// Errors returned across the api boundary. Callers compare with
// errors.Is.
var (
	// ErrAlertNotFound is returned by GetAlert / UpdateAlertStatus
	// when the id doesn't exist.
	ErrAlertNotFound = errors.New("detection: alert not found")

	// ErrInvalidAlertTransition is returned when UpdateAlertStatus is called with a status that doesn't follow from the row's current
	// status (e.g. resolved -> open). Mapped to 400 by the operator handler.
	ErrInvalidAlertTransition = errors.New("detection: invalid alert status transition")

	// ErrInvalidUserUpdater is returned when UpdateAlertStatus is called with a user_id that the identity context does not recognise.
	// Replaces the FK-level rejection that fk_alerts_updated_by enforced in the pre-bounded-context schema.
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
