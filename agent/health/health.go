// Package health tracks the agent's per-component health as an extensible set of conditions and reports them to the server as an
// idempotent snapshot (POST /api/status, issue #359). The first two components are the endpoint-security and network system extensions,
// whose XPC connectivity the receiver loops feed in via MarkConnected / MarkDisconnected. The wire shape mirrors the server's
// endpoint/api StatusReport; the agent builds the JSON itself (the two sides share no Go module) and a server-side PBT pins the contract.
package health

import (
	"fmt"
	"sort"
	"strings"
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
	// ComponentWindowsETWSensor is the health component for the Windows ETW process sensor (ADR-0018). The component vocabulary is open
	// (the server stores unrecognized types verbatim), so adding a platform-specific component needs no server change.
	ComponentWindowsETWSensor = "windows_etw_sensor"

	reasonActivated      = "activated"
	reasonNeverConnected = "never_connected"
	reasonConnectionLost = "connection_lost"
	// Provider-liveness reasons for the network extension (issue #649). Its XPC listener starts before its providers do, so an
	// established XPC session has never been evidence that anything is capturing: a process with no running provider reported
	// healthy while the host produced no network or DNS telemetry for 24+ hours. These reasons are what that state now looks like.
	// The reason vocabulary is open by contract (server/endpoint/api/status.go), so adding to it needs no server change.
	reasonAwaitingProviders  = "awaiting_provider_status"
	reasonNoProvidersRunning = "no_providers_running"
	reasonProviderStopped    = "provider_stopped"
	// reasonProviderStateUnknown is for a provider state this build does not recognise, which a newer extension can
	// produce. Distinct from the reasons above so an operator can tell "I do not know" from "I checked and it is down".
	reasonProviderStateUnknown = "provider_state_unknown"
	// reasonSelfHealFailed distinguishes "automatic recovery is still working on it" from "automatic recovery gave up and a
	// human is needed" (issue #632). Without the distinction an operator watching provider_stopped cannot tell a transient
	// stop the agent is about to fix from one it has already failed to fix three times, which is the difference between
	// ignoring the alert and driving to the host.
	reasonSelfHealFailed = "self_heal_failed"
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
	Inventory    *Inventory  `json:"inventory,omitempty"`
}

// Inventory is the host identity block carried on every status report (issue #579): the server refreshes the host's enrollment-time
// identity from it, so a hostname rename or OS upgrade reaches the console without a re-enroll (the agent's version rides the report's
// top-level agent_version field). The JSON tags match the server's api.Inventory exactly. Fields whose source was unavailable are sent
// empty; the server preserves its previously stored value for an empty field.
type Inventory struct {
	Hostname  string `json:"hostname"`
	OSName    string `json:"os_name"`
	OSVersion string `json:"os_version"`
	OSBuild   string `json:"os_build"`
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

// providerHealth is the remembered state of ONE capture provider inside a parent component's latest liveness report.
//
// It is not a componentState: a provider is never Registered, and it disappears from the snapshot the moment the extension
// stops reporting it. Only the transition instant is remembered between reports, so an age can be reported honestly.
type providerHealth struct {
	state            string
	lastTransitionNs int64
}

// Registry is the agent's concurrency-safe health state. Each monitored component is registered once at startup (seeding
// unhealthy/never_connected) and then driven by the receiver loops' connect/disconnect transitions. The poster reads Snapshot(); a
// buffered Changed() channel pulses on any status transition so the poster can report promptly rather than waiting for its periodic tick.
type Registry struct {
	mu    sync.Mutex
	comps map[string]*componentState
	order []string // registration order, for a stable Snapshot
	// providers is the per-parent-component view of the LATEST liveness report: parent component type -> provider -> state.
	//
	// Rendered into the snapshot rather than accumulated as registered components, which is the whole point (issue #702).
	// Liveness is level state and so is the snapshot, so a provider the extension stops reporting must vanish from the
	// snapshot too. The alternative, registering each provider on first sighting, would leave a provider an operator
	// deliberately switched off asserting "running" forever, and a stale positive claim is worse than silence: the server
	// contradicts that claim against arriving telemetry, so it would report a wedge on a provider that is simply off.
	providers map[string]map[string]providerHealth
	nowNs     func() int64
	changed   chan struct{}
}

// NewRegistry returns an empty registry using the wall clock. Tests inject a clock via newRegistryWithClock.
func NewRegistry() *Registry {
	return newRegistryWithClock(func() int64 { return time.Now().UnixNano() })
}

func newRegistryWithClock(nowNs func() int64) *Registry {
	return &Registry{
		comps:     map[string]*componentState{},
		providers: map[string]map[string]providerHealth{},
		nowNs:     nowNs,
		changed:   make(chan struct{}, 1),
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

// Provider states as they appear on the wire from the extension. A provider that has never started is ABSENT from the map rather
// than carrying a state, which is what lets "never started" and "started then stopped" grade differently. A deliberate stop (an
// operator disabling the opt-in DNS proxy) is reported as absence too, so it does not read as a fault forever.
const (
	ProviderRunning = "running"
	ProviderStopped = "stopped"
)

// Provider wire identifiers this build knows by name. The set is NOT closed: the extension owns the vocabulary and an
// unrecognised provider is still reported, under its own identifier (issue #702). These exist so the known two get a human
// display name and so the server and agent share one spelling.
const (
	ProviderContentFilter = "content_filter"
	ProviderDNSProxy      = "dns_proxy"
)

// GradeProviders grades a provider-liveness snapshot into a component status. Pure, so every case is unit-testable without a
// registry or a live extension.
//
// An empty map means the extension is up and talking but nothing is capturing: that is the #649 failure, and it is unhealthy even
// though the XPC session is perfectly healthy. A provider reported stopped is a fault the extension chose to surface (a deliberate
// stop is filtered out extension-side and arrives as absence). Anything else is running.
func GradeProviders(displayName string, providers map[string]string) (Status, string, string) {
	stopped := make([]string, 0, len(providers))
	running := 0
	for name, state := range providers {
		switch state {
		case ProviderStopped:
			stopped = append(stopped, name)
		case ProviderRunning:
			running++
		}
	}
	sort.Strings(stopped)
	switch {
	case len(stopped) > 0:
		return StatusUnhealthy, reasonProviderStopped,
			fmt.Sprintf("%s stopped capturing: %s", displayName, strings.Join(stopped, ", "))
	case running == 0:
		return StatusUnhealthy, reasonNoProvidersRunning, displayName + " is running but no capture provider started"
	default:
		return StatusHealthy, reasonActivated, displayName + " connected"
	}
}

// MarkProviders records a provider-liveness snapshot for compType, replacing whatever the XPC session alone implied. No-op for an
// unregistered type.
func (r *Registry) MarkProviders(compType string, providers map[string]string, decoded bool) {
	r.transition(compType, func(s *componentState) {
		s.everConnected = true
		status, reason, message := GradeProviders(s.displayName, providers)
		s.set(status, reason, message)
	})
	// Only a report we could actually READ may change the per-provider view, which is the same rule the durable transition
	// recorder applies (issue #649 gives the caller a Decoded flag for exactly this).
	//
	// The distinction is not pedantic. An undecodable report arrives as an empty provider map, indistinguishable by value
	// from the extension legitimately saying "nothing is running". Acting on it would clear every provider component and the
	// next good report would re-add them with fresh transition instants, so a decode failure would manufacture a round of
	// provider transitions and reset every age an operator reads. The parent's grading above is left on its pre-existing
	// path deliberately; narrowing that is a separate behaviour change.
	//
	// decoded is a parameter rather than a second method the caller must remember to call, because a caller that does not
	// know whether the report decoded cannot use this correctly, and the type should say so.
	if decoded {
		r.recordProviders(compType, providers)
	}
}

// recordProviders folds a liveness report into the per-provider view the snapshot renders (issue #702).
//
// Two rules, and both matter to the server that reads the result:
//
//   - A provider MISSING from the report is dropped, not retained. The extension reports a deliberate opt-out by omission,
//     so retaining the last known state would publish "running" for a provider an operator switched off.
//   - A provider whose state is unchanged keeps its transition instant. Reports arrive on every handshake, so re-stamping
//     each time would make every provider look like it had just changed and destroy the age the console shows.
//
// It is a no-op for an unregistered parent, matching transition, so a stray report cannot conjure providers under a
// component this build does not monitor.
func (r *Registry) recordProviders(compType string, providers map[string]string) {
	r.mu.Lock()
	if _, ok := r.comps[compType]; !ok {
		r.mu.Unlock()
		return
	}
	now := r.nowNs()
	previous := r.providers[compType]
	current := make(map[string]providerHealth, len(providers))
	changed := len(previous) != len(providers)
	for name, state := range providers {
		if was, ok := previous[name]; ok && was.state == state {
			current[name] = was
			continue
		}
		current[name] = providerHealth{state: state, lastTransitionNs: now}
		changed = true
	}
	r.providers[compType] = current
	r.mu.Unlock()
	if changed {
		r.notify()
	}
}

// MarkAwaitingProviders records that compType has an XPC session but has not yet said which providers are running. Degraded rather
// than healthy: connectivity is no longer taken as proof of capture. In practice this lasts milliseconds, because the extension
// re-publishes liveness on every hello; it persists only against an extension too old to report, where "we do not know" is the
// honest answer. No-op for an unregistered type.
func (r *Registry) MarkAwaitingProviders(compType string) {
	r.transition(compType, func(s *componentState) {
		s.everConnected = true
		s.set(StatusDegraded, reasonAwaitingProviders, s.displayName+" connected; awaiting provider status")
	})
}

// MarkSelfHealFailed records that automatic recovery exhausted its attempts for compType and a human is now required
// (issue #632). Unhealthy like the provider_stopped state it replaces, but under a distinct reason so an operator can tell
// a stop the agent is still working on from one it has already given up on.
//
// Deliberately NOT sticky: the next provider report calls MarkProviders and overwrites this, so a provider that comes back
// by any route (a later manual activate, a reboot, an operator toggle) clears the escalation without needing its own reset
// path. No-op for an unregistered type.
func (r *Registry) MarkSelfHealFailed(compType, message string) {
	r.transition(compType, func(s *componentState) {
		s.set(StatusUnhealthy, reasonSelfHealFailed, s.displayName+": "+message)
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
		// Each parent's providers follow it, so the list reads as a hierarchy even though the wire is flat.
		out = append(out, r.providerComponents(t)...)
	}
	return out
}

// providerComponents renders one parent's latest liveness report as its own components (issue #702).
//
// The server needs each provider's state as a POSITIVE claim it can contradict against arriving telemetry. Collapsed into
// one component, "the network extension is healthy" says nothing about which of its providers are capturing, so a wedged
// provider and a fully working host are indistinguishable on the wire.
//
// Sorted by name so the snapshot is stable across reports; the wire is compared as a whole by the server's last-writer-wins
// upsert, and map iteration order would make every report look different.
//
// Caller holds the lock.
func (r *Registry) providerComponents(compType string) []Component {
	// No early return for the empty case: an empty slice falls out of the loops below, and returning a literal nil here
	// instead puts a nil into Snapshot's append chain, which nilaway then traces to every caller that indexes the result.
	states := r.providers[compType]
	names := make([]string, 0, len(states))
	for name := range states {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Component, 0, len(names))
	for _, name := range names {
		p := states[name]
		status, reason, message := gradeProvider(name, p.state)
		out = append(out, Component{
			Type:             name,
			Status:           status,
			Reason:           reason,
			Message:          message,
			LastTransitionNs: p.lastTransitionNs,
		})
	}
	return out
}

// gradeProvider maps ONE provider's reported state to a component condition.
//
// A state this build does not recognise grades to unknown rather than to healthy or unhealthy. That is the honest answer
// for a newer extension reporting a state this agent predates, and it is also the safe one in both directions: it is not a
// positive "running" claim the server could contradict into a false alert, and it does not condemn a host either. The
// server's rollup treats a lone unknown as not raising the overall status, so this cannot turn a healthy host amber.
func gradeProvider(name, state string) (Status, string, string) {
	display := providerDisplayName(name)
	switch state {
	case ProviderRunning:
		return StatusHealthy, reasonActivated, display + " is capturing"
	case ProviderStopped:
		return StatusUnhealthy, reasonProviderStopped, display + " stopped capturing"
	default:
		return StatusUnknown, reasonProviderStateUnknown, display + " reported an unrecognized state"
	}
}

// providerDisplayName gives the known providers a human name and falls back to the wire identifier for one this build does
// not know, so a newer extension's provider is still legible rather than blank.
func providerDisplayName(name string) string {
	switch name {
	case ProviderContentFilter:
		return "Content filter"
	case ProviderDNSProxy:
		return "DNS proxy"
	default:
		return name
	}
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
