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
// (source, host_id, rule_id, subject) keeps app-control alerts
// distinct from any catalog-rule id collision. These alerts are
// process-backed, so the engine sets subject to the process id.
type ApplicationControlBlock struct{}

// applicationControlBlockEventType is the well-known event_type the extension emits when an AUTH_EXEC is denied. Stable wire-shape
// string; mirrored on the Swift side in `extension/edr/extension/EventSerializer.swift`.
const applicationControlBlockEventType = "application_control_block"

func (r *ApplicationControlBlock) ID() string { return "application_control_block" }

// NonDetectionKind declares this a projection, not a detection, so it stays off the operator-facing catalog surfaces
// (GET /api/rules, GET /api/attack-coverage, docs/detection-rules.md). Nothing about registration, evaluation or alert
// persistence changes. The blocking decision was already made on the host by the AUTH_EXEC walker; this rule renders it as an
// alert row, which is why its findings carry the matched app-control rule's id and severity from the payload rather than its own,
// and why Techniques() is empty.
func (r *ApplicationControlBlock) NonDetectionKind() api.NonDetectionKind {
	return api.NonDetectionProjection
}

// SupportedExclusionMatchTypes returns nil: this rule consults no exclusions, so the admin UI offers none for it (issue #520).
func (r *ApplicationControlBlock) SupportedExclusionMatchTypes() []api.ExclusionMatchType { return nil }

// DisplayName is the canonical name for the rule's catalog entry (Doc().Title). Unlike the other rules, the alert this rule raises
// does NOT carry DisplayName as its title: each block event maps to a finding whose RuleID is the matched app-control rule
// (`app_control:<n>`, not this catalog ID) and whose title is computed per block (`Application blocked: <binary>`), so the operator
// sees which binary was blocked by which admin rule. The finding-title==DisplayName invariant is enforced by the fixture-replay
// harness, which this rule IS now replayed by (issue #773 gave it fixtures). It is exempt there because it reports
// NonDetectionProjection above, not because it avoids the harness, and TestAll_NonDetectionClassification pins that set so the
// exemption cannot be widened (issue #519).
func (r *ApplicationControlBlock) DisplayName() string { return "Application control block" }

// Techniques returns an empty slice. App-control blocks are not mapped to MITRE ATT&CK because the framework's perspective is "the
// adversary did something": a successful block is the absence of that. Operators who want ATT&CK badging on app-control alerts can
// tag the originating rule downstream.
func (r *ApplicationControlBlock) Techniques() []string { return []string{} }

func (r *ApplicationControlBlock) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Surfaces every AUTH_EXEC denial from the extension as an alert in the unified view.",
		Description: "The extension's AUTH_EXEC decision walker denies execs that match an admin-defined " +
			"application-control rule. Every such denial emits an `application_control_block` event that this " +
			"built-in rule maps to an alert with `source='application_control'`. The alert carries the matched " +
			"rule's identifier, severity, and operator-supplied custom message. The dedup key " +
			"(source, host_id, rule_id, subject), where an app-control alert's subject is its process id, means " +
			"repeated blocks of the same binary by the same rule on the same process collapse into one alert row.",
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

// Evaluate maps each accepted block event to a Finding. Missing process row → defer the batch while the event is still inside the
// materialization grace window (resolveSubjectProcess raises the retryable miss, which this loop records without abandoning the
// remaining events, so the processor re-evaluates once the graph builder commits the exec); once the event is past that window the
// row is assumed never to arrive and the event is skipped. Missing or malformed payload fields → skip; these checks are this rule's
// OWN gate, not a backstop behind an earlier one. Ingest validates the event envelope only (event_id, host_id, event_type,
// timestamp_ns, plus host pinning) and never unmarshals or schema-validates the payload, so a malformed
// application_control_block payload reaches this rule intact and is dropped here or nowhere.
func (r *ApplicationControlBlock) Evaluate(ctx context.Context, events []api.Event, gr api.GraphReader) ([]api.Finding, error) {
	var findings []api.Finding
	var miss pendingMiss
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
		proc, err := resolveSubjectProcess(ctx, gr, evt, p.PID)
		if fatal := miss.absorb(err); fatal != nil {
			return fatalResult(findings, fmt.Errorf("application control block: %w", fatal))
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
	if miss.err != nil {
		return findings, fmt.Errorf("application control block: %w", miss.err)
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

// blockAlertDescription prefers the operator's custom message (the `custom_msg` the rule was created with) so admins can author the
// exact text that lands in the alert. Falls back to a deterministic default that names the rule type + identifier when no custom
// message is set, per the server-detection-rules-engine delta spec.
func blockAlertDescription(p applicationControlBlockPayload) string {
	if p.CustomMsg != nil && *p.CustomMsg != "" {
		return *p.CustomMsg
	}
	return fmt.Sprintf("Blocked %s rule for %s", p.RuleType, p.Identifier)
}
