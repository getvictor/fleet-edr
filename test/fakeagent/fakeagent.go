// Package fakeagent generates EDR event-envelope timelines from YAML scenarios and feeds them either through the M2 headless agent's
// unix-socket control plane (FeedControlPlane) or directly to a server's ingest endpoint (PostDirect). It is the substrate that the
// UAT plan's L3 headless-agent-plus-server integration tests (milestone M4), the L6 detection-efficacy corpus (M10), and the eventual
// Playwright fixtures + scale tests (M12) all share.
//
// The scenario format is documented in docs/testing-strategy.md. A starter set lives under scenarios/.
//
// The wire envelope this package emits is the same one the production agent emits (see schema/events.json): an array of
//
//	{event_id, host_id, timestamp_ns, event_type, payload}
//
// where payload is a per-event-type object. The same struct types serialise to both YAML (scenario authoring) and JSON (wire format)
// via the sigs.k8s.io/yaml adapter which delegates to encoding/json under the hood, so JSON tags are the single source of truth.
package fakeagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"sigs.k8s.io/yaml"
)

// Scenario is the in-memory representation of a YAML scenario file. Loaded by LoadScenario; fed through the control plane or posted
// direct by the methods on this type.
type Scenario struct {
	// Name is a human label used in log lines and test failures.
	Name string `json:"name"`

	// MITRE is the optional ATT&CK technique identifier (e.g. "T1059.004"). M10's efficacy corpus uses it to map scenarios to
	// detection assertions; M3 just preserves the field.
	MITRE string `json:"mitre,omitempty"`

	// Host carries the per-host metadata stamped on every envelope's host_id field. ID may be overridden at run time via WithHostID.
	Host Host `json:"host"`

	// Timeline is the ordered list of events the scenario will emit. The library does not sort by At; the YAML author owns ordering.
	Timeline []Event `json:"timeline"`

	// Assertions are parsed but not consumed in M3. M4's CI integration test and M10's efficacy harness will read them.
	Assertions []Assertion `json:"assertions,omitempty"`
}

// Host is the scenario's host metadata. ID is required; hostname + OS are optional context that may be used later for synthesised
// enrollment payloads.
type Host struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
}

// Event is a single timeline entry. The struct is intentionally flat with omitempty everywhere: the union of all event-type payloads
// is small, and a flat shape keeps both YAML authoring (no nesting per type) and JSON wire emission ergonomic. Type drives which
// fields are honoured in the emitted payload; fields irrelevant to Type are zero-valued and dropped by the per-type marshaller.
type Event struct {
	// At is the offset from the scenario's start time. Generated envelopes get timestamp_ns = startTime + At.nanoseconds.
	At Duration `json:"at"`

	// Type is the event_type written into the wire envelope. Must be one of the values in schema/events.json's event_type enum.
	Type string `json:"type"`

	// Common process-graph fields.
	PID  int `json:"pid,omitempty"`
	PPID int `json:"ppid,omitempty"`
	UID  int `json:"uid,omitempty"`
	GID  int `json:"gid,omitempty"`

	// fork specifics.
	ChildPID  int `json:"child_pid,omitempty"`
	ParentPID int `json:"parent_pid,omitempty"`

	// exec specifics.
	Path string   `json:"path,omitempty"`
	Args []string `json:"args,omitempty"`
	CWD  string   `json:"cwd,omitempty"`

	// exit specifics.
	ExitCode   int    `json:"exit_code,omitempty"`
	ExitReason string `json:"exit_reason,omitempty"`

	// open specifics.
	Flags int `json:"flags,omitempty"`

	// network_connect specifics.
	Protocol      string `json:"protocol,omitempty"`
	Direction     string `json:"direction,omitempty"`
	LocalAddress  string `json:"local_address,omitempty"`
	LocalPort     int    `json:"local_port,omitempty"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    int    `json:"remote_port,omitempty"`

	// dns_query specifics.
	QueryName         string   `json:"query_name,omitempty"`
	QueryType         string   `json:"query_type,omitempty"`
	ResponseAddresses []string `json:"response_addresses,omitempty"`

	// btm_launch_item_add specifics. The rule's decision input is the registered executable's code-signing:
	// ExecutableCodeSigningPresent emits the executable_code_signing object (set false to model "signing unreadable",
	// which the rule skips); ExecutableTeamID / ExecutableIsPlatformBinary / ExecutableIsNotarized fill it. The
	// Instigator* fields populate the forensic-only instigator_code_signing object (emitted when InstigatorPID > 0).
	ItemType                     string `json:"item_type,omitempty"`
	ItemPath                     string `json:"item_path,omitempty"`
	ExecutablePath               string `json:"executable_path,omitempty"`
	Legacy                       bool   `json:"legacy,omitempty"`
	Managed                      bool   `json:"managed,omitempty"`
	ExecutableCodeSigningPresent bool   `json:"executable_code_signing_present,omitempty"`
	ExecutableTeamID             string `json:"executable_team_id,omitempty"`
	ExecutableIsPlatformBinary   bool   `json:"executable_is_platform_binary,omitempty"`
	ExecutableIsNotarized        bool   `json:"executable_is_notarized,omitempty"`
	InstigatorPID                int    `json:"instigator_pid,omitempty"`
	InstigatorTeamID             string `json:"instigator_team_id,omitempty"`
	InstigatorIsPlatformBinary   bool   `json:"instigator_is_platform_binary,omitempty"`
}

// Assertion is the M4/M10 detection-assertion shape. Parsed by M3 for forward compatibility but not consumed.
type Assertion struct {
	Within   Duration `json:"within"`
	Rule     string   `json:"rule"`
	Severity string   `json:"severity"`
}

// Duration is a YAML-friendly wrapper around time.Duration. YAML naturally serialises Go durations as strings like "10ms" or "5s"
// when parsed via the standard library, but the sigs.k8s.io/yaml path goes via JSON, which renders time.Duration as an integer of
// nanoseconds. This wrapper parses the human-friendly string form so scenarios can use "10ms"/"5s"/"1h" idiomatically.
type Duration time.Duration

// UnmarshalJSON accepts either a JSON string ("10ms", "5s") or a JSON number (nanoseconds). The string form is what scenario
// authors write; the number form lets test code round-trip Envelopes back through encoding/json without losing precision. Both
// branches delegate to encoding/json so escape sequences, overflow, and malformed-quoting cases are all handled by the stdlib's
// well-fuzzed parser rather than a hand-rolled byte loop.
func (d *Duration) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return errors.New("duration: empty input")
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("duration: invalid quoted value: %w", err)
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("duration %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	// Bare number: nanoseconds. json.Unmarshal into int64 rejects floats, overflow, and non-numeric tokens with a typed error.
	var ns int64
	if err := json.Unmarshal(data, &ns); err != nil {
		return fmt.Errorf("duration: expected string or integer nanoseconds, got %q: %w", data, err)
	}
	*d = Duration(ns)
	return nil
}

// MarshalJSON emits the duration as its native Go-string form so a round-trip through the YAML loader plus a subsequent JSON dump
// yields a human-readable scenario rather than a wall of nanoseconds.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

// LoadScenario reads a YAML scenario file from path and validates the minimum invariants the scenario relies on (non-empty name,
// non-empty host id, at least one timeline entry, recognized event_type strings). It returns a fully populated Scenario or a
// diagnostic error that names the offending file and field so a test failure points the author at the right place.
func LoadScenario(path string) (*Scenario, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path comes from test code, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("fakeagent: read %s: %w", path, err)
	}
	var s Scenario
	if err := yaml.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("fakeagent: parse %s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("fakeagent: validate %s: %w", path, err)
	}
	return &s, nil
}

// Validate enforces the structural invariants every scenario must hold for the envelope builder + feeder to produce well-formed
// wire output. Called automatically by LoadScenario; exposed so test code that constructs a Scenario in-memory can re-run the same
// checks without a temp file round trip.
func (s *Scenario) Validate() error {
	if s.Name == "" {
		return errors.New("name is required")
	}
	if s.Host.ID == "" {
		return errors.New("host.id is required")
	}
	if len(s.Timeline) == 0 {
		return errors.New("timeline must contain at least one event")
	}
	for i, ev := range s.Timeline {
		if !knownEventTypes[ev.Type] {
			return fmt.Errorf("timeline[%d]: unknown event_type %q", i, ev.Type)
		}
	}
	return nil
}

// knownEventTypes mirrors the enum in schema/events.json. application_control_block is omitted: those are emitted reactively by the
// agent in response to server-pushed app-control rules, not produced by attack-corpus scenarios.
var knownEventTypes = map[string]bool{
	"exec":                true,
	"fork":                true,
	"exit":                true,
	"open":                true,
	"network_connect":     true,
	"dns_query":           true,
	"snapshot_heartbeat":  true,
	"btm_launch_item_add": true,
}
