package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/fleetdm/edr/server/rules/api"
)

// PrivilegeLaunchdPlistWrite fires when a system-domain LaunchDaemon is
// registered with Background Task Management (BTM) whose REGISTERED
// EXECUTABLE is not an Apple platform binary and not on the operator's
// team-ID allowlist: the canonical system-domain persistence vector
// (T1543.004). Registering a LaunchDaemon gives the attacker a
// root-running launch item on the next `launchctl bootstrap system/<name>`
// or reboot.
//
// The rule keys on `ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`
// (`item_type == "daemon"`), surfaced by the extension as a
// `btm_launch_item_add` event (ADR-0008 and its 2026-05-29 amendment). BTM
// fires on registration regardless of how the plist landed on disk.
//
// The decision rides the REGISTERED EXECUTABLE's code-signing, NOT the BTM
// instigator: a `launchctl bootstrap` registration is instigated by Apple's
// `smd`, so the instigator is always a platform binary and cannot
// discriminate (ground-truthed on edr-dev). We skip:
//   - `managed` items (MDM-deployed daemons are operator-legitimate),
//   - executables Apple signs as platform binaries,
//   - executables whose team ID matches a team_id exclusion in the detection-config surface,
//   - registrations whose executable code-signing we cannot read: a
//     high-precision skip.
//
// The alert is process-optional: the registered executable has no live
// process at registration and the instigator is not the attacker, so the
// finding carries no ProcessID and dedups on the item path.
type PrivilegeLaunchdPlistWrite struct {
	// Exclusions is the per-host false-positive resolver. A registration whose registered-executable team ID matches an exclusion
	// (match type team_id) is silently accepted, in addition to the always-trusted Apple platform binaries. Nil excludes nothing.
	Exclusions api.ExclusionResolver
}

func (r *PrivilegeLaunchdPlistWrite) ID() string { return "privilege_launchd_plist_write" }

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519). The ID stays the stale-but-stable
// snake_case identifier (renaming it is a migration-backed change); the prose name reflects what the rule actually detects today.
func (r *PrivilegeLaunchdPlistWrite) DisplayName() string { return "LaunchDaemon persistence" }

// Techniques returns the MITRE ATT&CK IDs this rule covers: T1543.004
// (Boot or Logon Autostart Execution → Launch Daemon).
func (r *PrivilegeLaunchdPlistWrite) Techniques() []string { return []string{"T1543.004"} }

// Doc surfaces the operator-facing description in /api/rules and
// the generated docs/detection-rules.md.
func (r *PrivilegeLaunchdPlistWrite) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags a system-domain LaunchDaemon whose registered executable is not an Apple platform binary and not allowlisted.",
		Description: "Detects the canonical system-domain persistence vector (T1543.004): a LaunchDaemon being registered " +
			"with macOS Background Task Management. Once registered, the next `launchctl bootstrap system/<name>` (or a " +
			"reboot) gives the attacker root-running persistence.\n\n" +
			"Keyed on the high-level `BTM_LAUNCH_ITEM_ADD` event (`item_type=daemon`) rather than a raw file write, so the " +
			"registration is caught no matter how the plist landed on disk (direct write, atomic temp-file+rename, copy), " +
			"which a file-write rule can miss.\n\n" +
			"The decision keys on the REGISTERED EXECUTABLE's code-signing, not on who registered it: a `launchctl " +
			"bootstrap` is always instigated by Apple's `smd`, so the instigator cannot discriminate. A daemon whose " +
			"executable is an Apple platform binary, MDM-managed, or signed by an allowlisted vendor team ID is skipped; " +
			"an ad-hoc, unsigned, or unknown-vendor executable fires. Paired with `persistence_launchagent` (user-domain " +
			"LaunchAgents).\n\n" +
			"Notarization is deliberately NOT a trust signal: it is an automated Apple scan, not an endorsement (Apple has " +
			"notarized malware), and is not checkable network-free on the ES callback thread. Trust is the operator's " +
			"team-ID allowlist; notarization, if ever used, belongs in a server-side reputation layer off the hot path.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"btm_launch_item_add"},
		FalsePositives: []string{
			"Non-Apple vendor app installing its own LaunchDaemon (a niche VPN, an in-house agent). Add a team_id exclusion for the vendor's signing team ID via the detection-config surface.",
			"Custom in-house pkg installers signed by an unexcluded developer team: add a team_id exclusion for that team ID.",
		},
		Limitations: []string{
			"BTM fires at item registration, not at the raw file-drop moment. A plist dropped on disk but never registered/loaded does not surface until registration (often deferred to reboot).",
			"Registrations whose executable code-signing cannot be read (executable absent or unreadable at registration) are skipped to stay high-precision.",
		},
	}
}

// btmLaunchItemAddPayload mirrors the extension's btm_launch_item_add wire shape (schema/events.json). The rule reads item_type +
// managed (the gate) and the REGISTERED EXECUTABLE's code-signing (the precision filter). instigator_pid / instigator_code_signing
// are forensic context only (the instigator is Apple's smd for launchctl-bootstrap registrations, so they cannot discriminate).
type btmLaunchItemAddPayload struct {
	ItemType              string           `json:"item_type"`
	ItemPath              string           `json:"item_path"`
	ExecutablePath        string           `json:"executable_path"`
	Managed               bool             `json:"managed"`
	ExecutableCodeSigning *codeSigningJSON `json:"executable_code_signing"`
	InstigatorPID         int              `json:"instigator_pid"`
	InstigatorCodeSigning *codeSigningJSON `json:"instigator_code_signing"`
}

// codeSigningJSON mirrors the extension's CodeSigning wire struct. The executable decision consumes team_id and
// is_platform_binary; the instigator copy carries the same shape but is forensic-only.
type codeSigningJSON struct {
	TeamID           string `json:"team_id"`
	IsPlatformBinary bool   `json:"is_platform_binary"`
}

func (r *PrivilegeLaunchdPlistWrite) Evaluate(
	ctx context.Context, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	return evalEachEvent(ctx, events, s, r.evalEvent)
}

// evalEvent ignores ctx + GraphReader: the decision is process-optional and rides the event payload alone (no
// pid->process correlation). The parameters are kept to satisfy the evalEachEvent evaluator signature.
func (r *PrivilegeLaunchdPlistWrite) evalEvent(
	_ context.Context, evt api.Event, _ api.GraphReader,
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
	// The decision rides the REGISTERED EXECUTABLE's code-signing, not the instigator (which is Apple's smd for a
	// launchctl-bootstrap registration; ADR-0008 amendment). No executable signing → we cannot classify the binary →
	// skip to stay high-precision (the executable is normally present and readable at registration).
	if p.ExecutableCodeSigning == nil {
		return nil, nil
	}
	if r.allowed(*p.ExecutableCodeSigning, evt.HostID) {
		return nil, nil
	}

	// Process-optional alert (ADR-0008 amendment): the registered executable has no live process at registration, and
	// the instigator (smd) is not the attacker, so there is no useful process link. ProcessID stays 0; the dedup Subject
	// is the item path so distinct daemons produce distinct alerts rather than colliding on process_id.
	executable := p.ExecutablePath
	if executable == "" {
		executable = "(unknown executable)"
	}
	return &api.Finding{
		HostID:   evt.HostID,
		RuleID:   r.ID(),
		Severity: api.SeverityHigh,
		Title:    r.DisplayName(),
		Description: fmt.Sprintf(
			"Untrusted executable %s registered as system LaunchDaemon %s: persistence (MITRE T1543.004)",
			executable, p.ItemPath,
		),
		Subject:  launchDaemonSubject(p.ItemPath),
		EventIDs: []string{evt.EventID},
	}, nil
}

// subjectColumnLimit mirrors alerts.subject VARCHAR(255) (server/detection/bootstrap/schema.go). A dedup subject longer
// than the column would fail the INSERT or silently truncate (and then collide), dropping the finding.
const subjectColumnLimit = 255

// launchDaemonSubject builds the process-less dedup subject for a LaunchDaemon registration. It keeps the human-readable
// "launchdaemon:<item path>" form for the common case, and falls back to a fixed-length SHA-256 of the path when the
// readable form would overflow alerts.subject. The hash is stable per item path, so dedup still collapses repeat
// registrations of the same daemon while keeping distinct daemons distinct.
func launchDaemonSubject(itemPath string) string {
	subject := "launchdaemon:" + itemPath
	if len(subject) <= subjectColumnLimit {
		return subject
	}
	sum := sha256.Sum256([]byte(itemPath))
	return "launchdaemon:sha256:" + hex.EncodeToString(sum[:])
}

// allowed returns true when the registered executable's code-signing identity is trusted for hostID: an Apple platform binary, or a
// binary whose team ID matches a team_id exclusion. Either short-circuits the finding. Notarization is deliberately not a trust
// signal here (Apple notarizes malware, and it is not checkable network-free on the ES thread); operator trust is the team-ID
// exclusion list, and any notarization/reputation scoring belongs server-side off the hot path.
func (r *PrivilegeLaunchdPlistWrite) allowed(cs codeSigningJSON, hostID string) bool {
	if cs.IsPlatformBinary {
		return true
	}
	return r.Exclusions != nil && r.Exclusions.Excluded(r.ID(), api.ExclusionMatchTeamID, cs.TeamID, hostID)
}
