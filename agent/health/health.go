// Package health tracks the agent's per-component health as an extensible set of conditions and reports them to the server as an
// idempotent snapshot (POST /api/status, issue #359). The first two components are the endpoint-security and network system extensions,
// whose XPC connectivity the receiver loops feed in via MarkConnected / MarkDisconnected. The wire shape mirrors the server's
// endpoint/api StatusReport; the agent builds the JSON itself (the two sides share no Go module) and a server-side PBT pins the contract.
package health

import (
	"sync"
	"time"
)

// Status is the closed set of component-health states, matching the server's HealthStatus enum. The server rejects a snapshot carrying
// any other status, so the agent only ever emits these four.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded" // reserved for future signals; unused by the first two extensions
	StatusUnhealthy Status = "unhealthy"
	StatusUnknown   Status = "unknown"
)

// Component type identifiers and reason codes reported today. Both are open vocabularies by contract (the server stores an unrecognized
// value verbatim); they are named here so the agent, the server, and the UI share one spelling for the first two signals.
const (
	ComponentEndpointSecurityExtension = "endpoint_security_extension"
	ComponentNetworkExtension          = "network_extension"

	reasonActivated      = "activated"
	reasonNeverConnected = "never_connected"
	reasonConnectionLost = "connection_lost"
)

// Component is one condition in a status snapshot. The JSON tags match the server's ComponentHealth exactly; reason and message are
// omitted when empty.
type Component struct {
	Type             string `json:"type"`
	Status           Status `json:"status"`
	Reason           string `json:"reason,omitempty"`
	Message          string `json:"message,omitempty"`
	LastTransitionNs int64  `json:"last_transition_ns"`
}

// report is the wire payload POSTed to /api/status. It carries the full component list every time and fully replaces the server's prior
// snapshot for this host (last-writer-wins); the host id is the authenticated identity the server derives from the bearer token, not a
// body field.
type report struct {
	AgentVersion string      `json:"agent_version"`
	ReportedAtNs int64       `json:"reported_at_ns"`
	Components   []Component `json:"components"`
}

// componentState is the registry's mutable per-component record. everConnected distinguishes a component that has never established a
// session (never_connected) from one that connected and then dropped (connection_lost).
type componentState struct {
	displayName      string
	status           Status
	reason           string
	message          string
	lastTransitionNs int64
	everConnected    bool
}

// Registry is the agent's concurrency-safe health state. Each monitored component is registered once at startup (seeding
// unhealthy/never_connected) and then driven by the receiver loops' connect/disconnect transitions. The poster reads Snapshot(); a
// buffered Changed() channel pulses on any status transition so the poster can report promptly rather than waiting for its periodic tick.
type Registry struct {
	mu      sync.Mutex
	comps   map[string]*componentState
	order   []string // registration order, for a stable Snapshot
	nowNs   func() int64
	changed chan struct{}
}

// NewRegistry returns an empty registry using the wall clock. Tests inject a clock via newRegistryWithClock.
func NewRegistry() *Registry {
	return newRegistryWithClock(func() int64 { return time.Now().UnixNano() })
}

func newRegistryWithClock(nowNs func() int64) *Registry {
	return &Registry{
		comps:   map[string]*componentState{},
		nowNs:   nowNs,
		changed: make(chan struct{}, 1),
	}
}

// Register seeds a component as unhealthy/never_connected with a human display name used to compose messages. Called once per component
// at startup so the first snapshot already reports a not-yet-activated extension (the #359 fresh-install gap) rather than omitting it.
// Registering the same type twice is a no-op after the first.
func (r *Registry) Register(compType, displayName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.comps[compType]; ok {
		return
	}
	r.comps[compType] = &componentState{
		displayName:      displayName,
		status:           StatusUnhealthy,
		reason:           reasonNeverConnected,
		message:          displayName + " not activated",
		lastTransitionNs: r.nowNs(),
	}
	r.order = append(r.order, compType)
}

// MarkConnected records that compType established a session: healthy/activated. No-op for an unregistered type.
func (r *Registry) MarkConnected(compType string) {
	r.transition(compType, func(s *componentState) {
		s.everConnected = true
		s.set(StatusHealthy, reasonActivated, s.displayName+" connected")
	})
}

// MarkDisconnected records that compType lost its session: unhealthy, with connection_lost if it had ever connected (the tamper-adjacent
// signal) or never_connected otherwise. No-op for an unregistered type.
func (r *Registry) MarkDisconnected(compType string) {
	r.transition(compType, func(s *componentState) {
		if s.everConnected {
			s.set(StatusUnhealthy, reasonConnectionLost, s.displayName+" connection lost")
			return
		}
		s.set(StatusUnhealthy, reasonNeverConnected, s.displayName+" not activated")
	})
}

// transition applies mutate under the lock, stamps the transition time only when the status actually changed, and pulses Changed() on a
// real change so "since when" stays meaningful and the poster does not wake for no-op updates.
func (r *Registry) transition(compType string, mutate func(*componentState)) {
	r.mu.Lock()
	s, ok := r.comps[compType]
	if !ok {
		r.mu.Unlock()
		return
	}
	before := s.status
	mutate(s)
	if s.status != before {
		s.lastTransitionNs = r.nowNs()
	}
	changed := s.status != before
	r.mu.Unlock()
	if changed {
		r.notify()
	}
}

// set updates the mutable fields of a component state in place. lastTransitionNs is stamped by transition, not here, so the stamp only
// advances on a real status change.
func (s *componentState) set(status Status, reason, message string) {
	s.status = status
	s.reason = reason
	s.message = message
}

// Snapshot returns the current conditions in registration order (stable so the wire bytes and any wire pin do not churn on map
// iteration order).
func (r *Registry) Snapshot() []Component {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Component, 0, len(r.order))
	for _, t := range r.order {
		s, ok := r.comps[t]
		if !ok {
			continue // order and comps are written together under the lock, so this is unreachable; the guard satisfies nil analysis.
		}
		out = append(out, Component{
			Type:             t,
			Status:           s.status,
			Reason:           s.reason,
			Message:          s.message,
			LastTransitionNs: s.lastTransitionNs,
		})
	}
	return out
}

// Changed returns a channel that receives a value after any status transition. It is buffered with capacity one and sent non-blocking,
// so a burst of transitions coalesces into a single pending wake-up (the poster debounces further).
func (r *Registry) Changed() <-chan struct{} { return r.changed }

func (r *Registry) notify() {
	select {
	case r.changed <- struct{}{}:
	default:
	}
}
