package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"path"

	"github.com/fleetdm/edr/server/rules/api"
)

// ApplicationControlBlock is the built-in pass-through rule that
// turns an `application_control_block` ingest event into an alert.
// The extension's AUTH_EXEC decision walker already made the
// blocking decision on the host; the rule's job here is to render
// that decision as a row in the unified alerts view so admins see it
// alongside catalog-rule findings.
//
// Unlike the catalog rules, this rule does not pattern-match over
// events: every accepted block event becomes a finding, with the
// rule_id and severity copied straight from the payload. Source is
// stamped AlertSourceApplicationControl so the dedup key
// (source, host_id, rule_id, process_id) keeps app-control alerts
// distinct from any catalog-rule id collision.
type ApplicationControlBlock struct{}

// applicationControlBlockEventType is the well-known event_type the
// extension emits when an AUTH_EXEC is denied. Stable wire-shape
// string; mirrored on the Swift side in
// `extension/edr/extension/EventSerializer.swift`.
const applicationControlBlockEventType = "application_control_block"

func (r *ApplicationControlBlock) ID() string { return "application_control_block" }

// Techniques returns an empty slice. App-control blocks are not
// mapped to MITRE ATT&CK because the framework's perspective is "the
// adversary did something" — a successful block is the absence of
// that. Operators who want ATT&CK badging on app-control alerts can
// tag the originating rule downstream.
func (r *ApplicationControlBlock) Techniques() []string { return []string{} }

func (r *ApplicationControlBlock) Doc() api.Documentation {
	return api.Documentation{
		Title:   "Application control block",
		Summary: "Surfaces every AUTH_EXEC denial from the extension as an alert in the unified view.",
		Description: "The extension's AUTH_EXEC decision walker denies execs that match an admin-defined " +
			"application-control rule. Every such denial emits an `application_control_block` event that this " +
			"built-in rule maps to an alert with `source='application_control'`. The alert carries the matched " +
			"rule's identifier, severity, and operator-supplied custom message. The dedup key " +
			"(source, host_id, rule_id, process_id) means repeated blocks of the same binary by the same rule on " +
			"the same process collapse into one alert row.",
		Severity:   api.SeverityMedium,
		EventTypes: []string{applicationControlBlockEventType},
	}
}

type applicationControlBlockPayload struct {
	PID           int     `json:"pid"`
	Path          string  `json:"path"`
	RuleID        string  `json:"rule_id"`
	RuleType      string  `json:"rule_type"`
	Identifier    string  `json:"identifier"`
	Severity      string  `json:"severity"`
	CustomMsg     *string `json:"custom_msg,omitempty"`
	CustomURL     *string `json:"custom_url,omitempty"`
	PolicyID      int64   `json:"policy_id"`
	PolicyVersion int64   `json:"policy_version"`
}

// Evaluate maps each accepted block event to a Finding. Missing
// process row → skip the event (the graph builder hasn't materialised
// the exec yet; the next batch will see it after re-ingest). Missing
// or malformed payload fields → skip; the validator at ingest is the
// authoritative gate, this rule is best-effort over the residual.
func (r *ApplicationControlBlock) Evaluate(ctx context.Context, events []api.Event, gr api.GraphReader) ([]api.Finding, error) {
	var findings []api.Finding
	for _, evt := range events {
		if evt.EventType != applicationControlBlockEventType {
			continue
		}
		var p applicationControlBlockPayload
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			continue
		}
		if p.RuleID == "" || p.Severity == "" {
			continue
		}
		proc, err := gr.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
		if err != nil {
			return nil, fmt.Errorf("application control block: get process pid %d: %w", p.PID, err)
		}
		if proc == nil {
			continue
		}
		findings = append(findings, api.Finding{
			HostID:      evt.HostID,
			RuleID:      p.RuleID,
			Source:      api.AlertSourceApplicationControl,
			Severity:    p.Severity,
			Title:       blockAlertTitle(p),
			Description: blockAlertDescription(p),
			ProcessID:   proc.ID,
			EventIDs:    []string{evt.EventID},
		})
	}
	return findings, nil
}

// blockAlertTitle renders the alert headline shown in the alerts
// list. Prefers the binary basename so a row like
// "Application blocked: Calculator" beats one that drowns the
// column in a full path.
//
// Uses `path.Base` (Unix-only, forward-slash) rather than
// `path/filepath.Base` (host-OS dependent). Agent paths are always
// macOS Unix-style; if the server ever ran on Windows, filepath would
// keep the full string under host=Windows because backslash is the
// separator there. path.Base is the correct semantic for the
// known-Unix input here, not just a cross-platform optimization.
func blockAlertTitle(p applicationControlBlockPayload) string {
	name := path.Base(p.Path)
	if name == "" || name == "." || name == "/" {
		name = p.Path
	}
	if name == "" {
		return "Application blocked"
	}
	return "Application blocked: " + name
}

// blockAlertDescription prefers the operator's custom message (the
// `custom_msg` the rule was created with) so admins can author the
// exact text that lands in the alert. Falls back to a deterministic
// default that names the rule type + identifier when no custom
// message is set, per the server-detection-rules-engine delta spec.
func blockAlertDescription(p applicationControlBlockPayload) string {
	if p.CustomMsg != nil && *p.CustomMsg != "" {
		return *p.CustomMsg
	}
	return fmt.Sprintf("Blocked %s rule for %s", p.RuleType, p.Identifier)
}
