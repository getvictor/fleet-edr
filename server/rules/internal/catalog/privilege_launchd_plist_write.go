package catalog

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fleetdm/edr/server/rules/api"
)

// PrivilegeLaunchdPlistWrite fires when a system-domain LaunchDaemon is
// registered with Background Task Management (BTM) by a non-Apple,
// non-allowlisted process — the canonical system-domain persistence
// vector (T1543.004). Registering a LaunchDaemon gives the attacker a
// root-running launch item on the next `launchctl bootstrap system/<name>`
// or reboot.
//
// The rule keys on `ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`
// (`item_type == "daemon"`), surfaced by the extension as a
// `btm_launch_item_add` event (ADR-0008). BTM is the high-level signal
// macOS 13+ emits when launchd registers the item, regardless of how the
// plist landed on disk — so unlike the previous `open`-based rule it also
// catches atomic temp-file+rename drops and `cp` by a platform binary.
//
// Precision: the BTM event carries the instigator process inline, so the
// decision reads the instigator's code-signing directly (no pid→process
// correlation, which also removes the open-vs-exec race the old rule had).
// We skip:
//   - `managed` items (MDM-deployed daemons are operator-legitimate),
//   - instigators Apple signs as platform binaries (installd, etc.),
//   - instigators whose team ID is on EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST,
//   - events with no instigator (boot-time / launchd-internal registrations
//     we cannot attribute) — high-precision skip, matching the old rule's
//     "no process row → no finding" guard.
type PrivilegeLaunchdPlistWrite struct {
	// AllowedTeamIDs is the set of code-signing team IDs whose LaunchDaemon registrations are silently accepted. Keep it small
	// — every entry is a deployment-trusted vendor (Munki, JumpCloud, Kandji, an in-house signing team, etc.).
	AllowedTeamIDs map[string]struct{}
}

func (r *PrivilegeLaunchdPlistWrite) ID() string { return "privilege_launchd_plist_write" }

// Techniques returns the MITRE ATT&CK IDs this rule covers — T1543.004
// (Boot or Logon Autostart Execution → Launch Daemon).
func (r *PrivilegeLaunchdPlistWrite) Techniques() []string { return []string{"T1543.004"} }

// Doc surfaces the operator-facing description in /api/rules and
// the generated docs/detection-rules.md.
func (r *PrivilegeLaunchdPlistWrite) Doc() api.Documentation {
	return api.Documentation{
		Title:   "LaunchDaemon persistence (BTM daemon registration)",
		Summary: "Flags a system-domain LaunchDaemon registered with Background Task Management by a non-Apple, non-allowlisted process.",
		Description: "Detects the canonical system-domain persistence vector (T1543.004): a LaunchDaemon being registered " +
			"with macOS Background Task Management. Once registered, the next `launchctl bootstrap system/<name>` (or a " +
			"reboot) gives the attacker root-running persistence.\n\n" +
			"Keyed on the high-level `BTM_LAUNCH_ITEM_ADD` event (`item_type=daemon`) rather than a raw file write, so it " +
			"catches the drop regardless of mechanism — including atomic temp-file+rename and `cp` by an Apple-signed " +
			"binary, which a file-write rule misses.\n\n" +
			"Paired with `persistence_launchagent` (user-domain LaunchAgents). To stay high-precision, registrations by " +
			"Apple platform binaries, MDM-managed items, and allowlisted vendor team IDs are skipped.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"btm_launch_item_add"},
		FalsePositives: []string{
			"Non-Apple vendor app installing its own LaunchDaemon (Docker, a VPN, an MDM agent). Allowlist the vendor's signing team ID via EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST.",
			"Custom in-house pkg installers signed by your developer team — same allowlist applies.",
		},
		Limitations: []string{
			"BTM fires at item registration, not at the raw file-drop moment. A plist dropped on disk but never registered/loaded does not surface until registration (often deferred to reboot).",
			"Registrations with no attributable instigator process (boot-time, launchd-internal) are skipped to stay high-precision.",
		},
		Config: []api.ConfigKnob{
			{
				EnvVar:      "EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST",
				Type:        "csv-team-ids",
				Default:     "",
				Description: "Comma-separated Apple Developer Program team IDs (10-character strings, e.g. `8VBZ3948LU`) whose LaunchDaemon registrations are accepted silently.",
			},
		},
	}
}

// btmLaunchItemAddPayload mirrors the extension's btm_launch_item_add wire shape (schema/events.json). The rule reads item_type +
// managed (the gate) and the instigator's code-signing (the precision filter); item_path / executable_path / instigator_pid are
// surfaced in the finding.
type btmLaunchItemAddPayload struct {
	ItemType              string           `json:"item_type"`
	ItemPath              string           `json:"item_path"`
	ExecutablePath        string           `json:"executable_path"`
	Managed               bool             `json:"managed"`
	InstigatorPID         int              `json:"instigator_pid"`
	InstigatorCodeSigning *codeSigningJSON `json:"instigator_code_signing"`
}

// codeSigningJSON mirrors the extension's CodeSigning wire struct. We only consume team_id + is_platform_binary.
type codeSigningJSON struct {
	TeamID           string `json:"team_id"`
	IsPlatformBinary bool   `json:"is_platform_binary"`
}

func (r *PrivilegeLaunchdPlistWrite) Evaluate(
	ctx context.Context, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	var findings []api.Finding
	for _, evt := range events {
		f, err := r.evalEvent(ctx, evt, s)
		if err != nil {
			return nil, err
		}
		if f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
}

func (r *PrivilegeLaunchdPlistWrite) evalEvent(
	ctx context.Context, evt api.Event, s api.GraphReader,
) (*api.Finding, error) {
	if evt.EventType != "btm_launch_item_add" {
		return nil, nil
	}
	var p btmLaunchItemAddPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		// Malformed BTM events are noise from a misbehaving extension build, not a detection signal. Drop and move on.
		return nil, nil
	}
	// System-domain LaunchDaemons only (T1543.004). LaunchAgents / login items are other techniques, handled elsewhere.
	if p.ItemType != "daemon" {
		return nil, nil
	}
	// MDM-managed daemons are operator-deployed by definition.
	if p.Managed {
		return nil, nil
	}
	// No attributable instigator → cannot confirm a non-Apple writer; skip to stay high-precision (matches the old rule's
	// "no process row → no finding" behaviour).
	if p.InstigatorCodeSigning == nil {
		return nil, nil
	}
	if r.allowed(*p.InstigatorCodeSigning) {
		return nil, nil
	}

	// Best-effort process-tree link: correlate the instigator PID to a process row for the finding's ProcessID. The DECISION
	// above does not depend on this (the instigator's signing rides inline), so a missing row only costs the UI link, never
	// the detection — unlike the old open-based rule, where a missing row dropped the finding entirely.
	var processID int64
	if proc, err := s.GetProcessByPID(ctx, evt.HostID, p.InstigatorPID, evt.TimestampNs); err != nil {
		return nil, fmt.Errorf("get process pid %d: %w", p.InstigatorPID, err)
	} else if proc != nil {
		processID = proc.ID
	}

	writer := p.ExecutablePath
	if writer == "" {
		writer = fmt.Sprintf("pid %d", p.InstigatorPID)
	}
	return &api.Finding{
		HostID:   evt.HostID,
		RuleID:   r.ID(),
		Severity: api.SeverityHigh,
		Title:    "LaunchDaemon persistence",
		Description: fmt.Sprintf(
			"%s registered system LaunchDaemon %s — non-Apple persistence (MITRE T1543.004)",
			writer, p.ItemPath,
		),
		ProcessID: processID,
		EventIDs:  []string{evt.EventID},
	}, nil
}

// allowed returns true when the instigator's code-signing identity is a platform binary or on the operator's team-ID allowlist —
// both short-circuit the finding.
func (r *PrivilegeLaunchdPlistWrite) allowed(cs codeSigningJSON) bool {
	if cs.IsPlatformBinary {
		return true
	}
	if r.AllowedTeamIDs == nil {
		return false
	}
	_, ok := r.AllowedTeamIDs[cs.TeamID]
	return ok
}
