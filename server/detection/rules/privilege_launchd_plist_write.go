package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/store"
)

// PrivilegeLaunchdPlistWrite fires on a write-mode `open(2)` against any
// `*.plist` directly under `/Library/LaunchDaemons/`. That directory is
// the canonical drop site for system-domain LaunchDaemons (T1543.004) —
// once a plist lands there, the next `launchctl bootstrap system/<name>`
// (or a reboot) gives the attacker root-running persistence.
//
// The rule is paired with `persistence_launchagent` (T1543.001), which
// catches the activation step for user-domain LaunchAgents via
// `launchctl load`. We deliberately catch this one at the file-write
// step rather than the activation step because LaunchDaemon activation
// is often deferred to reboot; the drop is the moment we want to surface.
//
// To stay high-precision we skip writers Apple itself signs as platform
// binaries (installd, system_installd, sysadminctl, package install
// post-flight scripts run as root, etc.) — those are the legitimate
// path for shipping a daemon. Operators with a non-Apple MDM agent that
// writes here (Munki, JumpCloud, Kandji's own daemon) can allowlist
// the agent's team ID via EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST.
//
// Known limitations, documented for the operator runbook:
//   - Atomic writes via temp-file + rename: ESF NOTIFY_OPEN sees the
//     temp file, not the destination, so the rule misses these. We
//     don't subscribe to NOTIFY_RENAME today; tracked for Phase 8.
//   - Drops via Apple platform binaries (e.g. attacker uses `sudo cp`
//     where `cp` is a platform binary): skipped here, but the parent
//     shell's exec is captured by suspicious_exec / process tree.
type PrivilegeLaunchdPlistWrite struct {
	// AllowedTeamIDs is the set of code-signing team IDs whose writes
	// to /Library/LaunchDaemons should be silently accepted. Keep it
	// small — every entry is a tenant-trusted vendor.
	AllowedTeamIDs map[string]struct{}
}

func (r *PrivilegeLaunchdPlistWrite) ID() string { return "privilege_launchd_plist_write" }

// Techniques returns the MITRE ATT&CK IDs this rule covers — T1543.004
// (Boot or Logon Autostart Execution → Launch Daemon).
func (r *PrivilegeLaunchdPlistWrite) Techniques() []string { return []string{"T1543.004"} }

// launchDaemonPath matches a plist directly under /Library/LaunchDaemons.
// The trailing `[^/]+` excludes nested paths (e.g.
// /Library/LaunchDaemons/foo/bar.plist isn't a real LaunchDaemon location)
// so the rule stays focused on the actual drop site.
var launchDaemonPath = regexp.MustCompile(`^/Library/LaunchDaemons/[^/]+\.plist$`)

// launchDaemonsBytes is the substring fast-path filter applied to the raw
// JSON payload before json.Unmarshal. ESF NOTIFY_OPEN fires on every file
// open in the kernel — thousands per second on a busy host — and well
// over 99.99% of those opens never touch /Library/LaunchDaemons. Skipping
// the JSON decode for opens that obviously don't qualify cuts the rule's
// CPU cost from "one unmarshal per open" to "one bytes.Contains per
// open". The substring can over-match (e.g. an open whose `path` happens
// to mention the directory name elsewhere in the JSON), but
// launchDaemonPath.MatchString below tightens it to the canonical drop
// site, so the gate is purely an optimisation, not a correctness check.
var launchDaemonsBytes = []byte("/Library/LaunchDaemons/")

// Bits 0 and 1 of the open(2) flags hold the access mode: O_RDONLY=0,
// O_WRONLY=1, O_RDWR=2. Anything non-zero in those two bits means the
// file descriptor can be written. This matches the kernel's interpretation
// regardless of whether higher bits (O_CREAT, O_TRUNC, O_APPEND, ...) are
// set, so a `cp -c` (which uses O_WRONLY|O_CREAT|O_TRUNC = 0x601 on
// Darwin) and a plain `cat > foo.plist` (O_WRONLY|O_CREAT|O_TRUNC) both
// trip the check.
const openAccessModeMask = 0x3

type openPayload struct {
	PID   int    `json:"pid"`
	Path  string `json:"path"`
	Flags int    `json:"flags"`
}

// codeSigningJSON mirrors the extension's CodeSigning struct on the wire.
// We only consume team_id + is_platform_binary; signing_id and flags
// stay on the row but the rule doesn't read them.
type codeSigningJSON struct {
	TeamID           string `json:"team_id"`
	IsPlatformBinary bool   `json:"is_platform_binary"`
}

func (r *PrivilegeLaunchdPlistWrite) Evaluate(
	ctx context.Context, events []store.Event, s *store.Store,
) ([]detection.Finding, error) {
	var findings []detection.Finding
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
	ctx context.Context, evt store.Event, s *store.Store,
) (*detection.Finding, error) {
	if evt.EventType != "open" {
		return nil, nil
	}
	// Substring fast-path: skip the JSON decode for the overwhelming
	// majority of opens that don't touch /Library/LaunchDaemons at all.
	// See launchDaemonsBytes for the rationale.
	if !bytes.Contains(evt.Payload, launchDaemonsBytes) {
		return nil, nil
	}
	var p openPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		// Malformed open events are noise from a misbehaving extension
		// build, not a detection signal. Drop and move on.
		return nil, nil
	}
	if !launchDaemonPath.MatchString(p.Path) {
		return nil, nil
	}
	if p.Flags&openAccessModeMask == 0 {
		// Read-only open. Tools like `plutil -p` enumerate plists
		// constantly; firing on those would bury operators in noise.
		return nil, nil
	}

	proc, err := s.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
	if err != nil {
		return nil, fmt.Errorf("get process pid %d: %w", p.PID, err)
	}
	if proc == nil {
		// Defensive: the open event landed before the writer's exec
		// row materialised. Same race as credential_keychain_dump; the
		// processor loop normally lands the row first, so this is a
		// guard, not a regular drop path.
		return nil, nil
	}
	if r.allowed(proc.CodeSigning) {
		return nil, nil
	}

	return &detection.Finding{
		HostID:   evt.HostID,
		RuleID:   r.ID(),
		Severity: detection.SeverityHigh,
		Title:    "LaunchDaemon plist drop",
		Description: fmt.Sprintf(
			"%s wrote %s — non-Apple persistence drop in system LaunchDaemons (MITRE T1543.004)",
			proc.Path, p.Path,
		),
		ProcessID: proc.ID,
		EventIDs:  []string{evt.EventID},
	}, nil
}

// allowed returns true when the writing process's code-signing identity
// is on the operator's allowlist or is a platform binary. Both branches
// short-circuit the finding. NullRawJSON is a json.RawMessage alias;
// both an empty slice (DB NULL → store.NullRawJSON.Scan zeros it) and
// the literal JSON value `null` (4 bytes) mean "no code_signing on the
// process row" — typically an unsigned binary, which we treat as
// in-scope so the finding fires.
func (r *PrivilegeLaunchdPlistWrite) allowed(raw store.NullRawJSON) bool {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return false
	}
	var cs codeSigningJSON
	if err := json.Unmarshal(raw, &cs); err != nil {
		return false
	}
	if cs.IsPlatformBinary {
		return true
	}
	if r.AllowedTeamIDs == nil {
		return false
	}
	_, ok := r.AllowedTeamIDs[cs.TeamID]
	return ok
}
