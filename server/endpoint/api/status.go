package api

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// HealthStatus is the closed set of health states a single component condition, and the server-computed per-host rollup, may hold. It
// is deliberately small and closed: the agent owns the open-ended `type` and `reason` vocabularies (so a new signal is an agent-only
// change), but the status is validated at the ingest boundary so the server, the rollup, and the UI badge all reason over four known
// values. Ordering for the rollup (worst-of) is unhealthy > degraded > healthy, with unknown reserved for "no component reported".
type HealthStatus string

const (
	HealthHealthy   HealthStatus = "healthy"   // the component is up and doing its job (an extension with a live XPC session)
	HealthDegraded  HealthStatus = "degraded"  // the component works but not fully (reserved for future signals; unused by the first two)
	HealthUnhealthy HealthStatus = "unhealthy" // the component is not doing its job (an extension that never connected or dropped)
	HealthUnknown   HealthStatus = "unknown"   // no state is known (a host that has never posted a snapshot rolls up to this)
)

// Valid reports whether s is one of the four known states. The check-in handler rejects a snapshot carrying any other component
// status; unknown `type` and `reason` strings are accepted verbatim, but the status enum is the one field held to a closed set.
func (s HealthStatus) Valid() bool {
	switch s {
	case HealthHealthy, HealthDegraded, HealthUnhealthy, HealthUnknown:
		return true
	default:
		return false
	}
}

// Component type identifiers reported today. These are open-vocabulary strings by contract (the server stores an unrecognized type
// verbatim), named here only for the two signals shipped first so the server, tests, and UI share one spelling.
const (
	ComponentEndpointSecurityExtension = "endpoint_security_extension" // the ESF system extension's XPC session
	ComponentNetworkExtension          = "network_extension"           // the network system extension's XPC session
)

// Reason codes reported today. Also open-vocabulary; named for the first two signals. never_connected is the fresh-install activation
// gap (issue #359); connection_lost is a component that connected and then dropped while the agent kept running (the tamper-adjacent
// signal a later alert rule will consume).
const (
	ReasonActivated      = "activated"       // the component reached a healthy session
	ReasonNeverConnected = "never_connected" // the component has not connected since the agent started
	ReasonConnectionLost = "connection_lost" // the component connected and then lost its session
)

// ComponentHealth is one condition in a host's status snapshot: a stable machine `Type`, a closed-enum `Status`, an open-vocabulary
// machine `Reason`, a human `Message` for the detail panel, and `LastTransitionNs`, the agent-observed instant the component entered
// its current status (so the UI can render "since 3m ago" and a later tamper rule can reason over the transition time). Reason and
// Message are omitted when empty; the pair is carried inside the snapshot's JSON, not mapped to its own columns, so it has no db tags.
type ComponentHealth struct {
	Type             string       `json:"type"`
	Status           HealthStatus `json:"status"`
	Reason           string       `json:"reason,omitempty"`
	Message          string       `json:"message,omitempty"`
	LastTransitionNs int64        `json:"last_transition_ns"`
}

// StatusReport is the wire payload the agent POSTs at /api/status. It is an idempotent snapshot, not an append: every post carries the
// full component list and fully replaces the server's prior view for that host (last-writer-wins, ordered by ReportedAtNs). The agent
// does not send the overall rollup; the server computes it from Components. Kept a distinct type from any persisted row so the agent
// contract is a plain DTO.
type StatusReport struct {
	AgentVersion string     `json:"agent_version"`
	ReportedAtNs int64      `json:"reported_at_ns"`
	Components   Components `json:"components"`
}

// Components is the list of component conditions persisted as a single MySQL JSON column and also carried on the wire. It mirrors the
// JSONStringSlice pattern (server/detection/api): an empty or nil slice round-trips through SQL NULL, so Scan(Value(empty)) is nil,
// and a host with no components rolls up to HealthUnknown rather than storing "[]".
type Components []ComponentHealth

// Scan implements sql.Scanner. SQL NULL and an empty payload both decode to a nil slice. A non-empty payload is unmarshaled directly:
// json.Unmarshal allocates fresh values for every field and does not retain the input slice, so the result never aliases the driver's
// reused scratch buffer (unlike NullRawJSON, which must copy because it stores the raw bytes verbatim).
func (c *Components) Scan(value any) error {
	if value == nil {
		*c = nil
		return nil
	}
	var b []byte
	switch v := value.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return fmt.Errorf("Components.Scan: unsupported type %T", value)
	}
	if len(b) == 0 {
		*c = nil
		return nil
	}
	return json.Unmarshal(b, c)
}

// Value implements driver.Valuer. An empty or nil slice maps to SQL NULL so the column round-trips cleanly.
func (c Components) Value() (driver.Value, error) {
	if len(c) == 0 {
		return nil, nil
	}
	return json.Marshal(c)
}

// Rollup computes the server-side overall health for a host from its component conditions: the worst status present. The precedence is
// unhealthy over degraded over healthy; a host with no reported component is unknown. The agent never sends this value; the server
// derives and stores it so the "what counts as unhealthy" policy can change without an agent redeploy. A component carrying the unknown
// status (a valid but not-actionable state) does not by itself condemn the host, so with at least one component present and none
// unhealthy or degraded the host rolls up to healthy; the unknown component still surfaces individually in the detail panel.
func Rollup(components Components) HealthStatus {
	if len(components) == 0 {
		return HealthUnknown
	}
	hasDegraded := false
	for _, c := range components {
		switch c.Status {
		case HealthUnhealthy:
			return HealthUnhealthy
		case HealthDegraded:
			hasDegraded = true
		case HealthHealthy, HealthUnknown:
			// Neither raises the rollup: healthy is the floor, and a lone unknown component does not by itself condemn the host.
		}
	}
	if hasDegraded {
		return HealthDegraded
	}
	return HealthHealthy
}
