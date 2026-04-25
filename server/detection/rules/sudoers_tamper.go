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

// SudoersTamper fires on a write-mode `open(2)` against `/etc/sudoers`
// or any direct child of `/etc/sudoers.d/`. Editing those files grants
// future shell sessions arbitrary command execution as root, so a
// successful tamper is an instant escalation primitive — T1548.003.
//
// The rule deliberately does NOT key on code-signing platform-binary
// status the way persistence_launchagent / privilege_launchd_plist_write
// do, because the canonical attacker tools for sudoers tampering are
// platform binaries themselves: `cp`, `tee`, shell redirection, even
// `sudo vi /etc/sudoers`. Filtering platform binaries would silence
// every realistic attack while admitting basically nothing else of
// interest. We fire on any non-allowlisted writer instead, and let
// operators tune via EDR_SUDOERS_WRITER_ALLOWLIST.
//
// Why visudo doesn't need to be in the default allowlist: visudo writes
// to /etc/sudoers.tmp (or $TMPDIR) and atomically renames it onto
// /etc/sudoers. ESF NOTIFY_OPEN doesn't fire on rename, and visudo
// never opens /etc/sudoers itself in write mode, so the rule doesn't
// see visudo's flow at all. Same is true for sudoedit. The rule only
// trips when something writes to /etc/sudoers directly.
//
// Known limitation: an attacker with root could create the temp file
// and rename it onto /etc/sudoers without ever firing NOTIFY_OPEN on
// /etc/sudoers. NOTIFY_RENAME would catch that, but the extension
// doesn't subscribe to it today (tracked for Phase 8 alongside the
// privilege_launchd_plist_write atomic-rename gap).
type SudoersTamper struct {
	// AllowedWriters is the set of absolute writer-process paths the
	// rule should silently accept. Populated from
	// EDR_SUDOERS_WRITER_ALLOWLIST. Empty by default — every direct
	// write to sudoers fires.
	AllowedWriters map[string]struct{}
}

func (r *SudoersTamper) ID() string { return "sudoers_tamper" }

// Techniques returns the MITRE ATT&CK IDs this rule covers — T1548.003
// (Abuse Elevation Control Mechanism: Sudo and Sudo Caching).
func (r *SudoersTamper) Techniques() []string { return []string{"T1548.003"} }

// sudoersPath matches /etc/sudoers itself and any direct child of
// /etc/sudoers.d/. ESF reports both forms (/etc/...  and
// /private/etc/... since /etc is a symlink); we accept either. Nested
// paths (/etc/sudoers.d/foo/bar) are excluded by `[^/]+` so the rule
// can't be lured by an attacker creating a same-named subdirectory
// somewhere unrelated.
var sudoersPath = regexp.MustCompile(`^(?:/private)?/etc/sudoers(?:\.d/[^/]+)?$`)

// sudoersBytes is the substring fast-path filter applied to the raw
// JSON payload before json.Unmarshal. NOTIFY_OPEN fires on every file
// open in the kernel — thousands per second — and writes to sudoers
// happen on a stable host literally never. Skipping the JSON decode
// for opens that obviously don't qualify cuts the rule's CPU cost
// from "one unmarshal per open" to "one bytes.Contains per open".
// Both /etc/sudoers and /private/etc/sudoers contain the same magic
// substring, so a single check covers both forms.
var sudoersBytes = []byte("/etc/sudoers")

// sudoersOpenPayload mirrors the open event shape we care about. Local
// to this rule rather than a shared package symbol so the
// privilege_launchd_plist_write rule (in flight on another branch) can
// keep its own copy without merge collisions; both can dedupe once
// both rules are on main.
type sudoersOpenPayload struct {
	PID   int    `json:"pid"`
	Path  string `json:"path"`
	Flags int    `json:"flags"`
}

// Bits 0 and 1 of open(2) flags hold the access mode: O_RDONLY=0,
// O_WRONLY=1, O_RDWR=2. Anything non-zero in those two bits means the
// fd can be written. Higher bits (O_CREAT, O_TRUNC, O_APPEND, ...)
// don't affect the access mode.
const sudoersWriteAccessMask = 0x3

func (r *SudoersTamper) Evaluate(
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

func (r *SudoersTamper) evalEvent(
	ctx context.Context, evt store.Event, s *store.Store,
) (*detection.Finding, error) {
	if evt.EventType != "open" {
		return nil, nil
	}
	if !bytes.Contains(evt.Payload, sudoersBytes) {
		return nil, nil
	}
	var p sudoersOpenPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return nil, nil
	}
	if !sudoersPath.MatchString(p.Path) {
		return nil, nil
	}
	if p.Flags&sudoersWriteAccessMask == 0 {
		// Read-only open. cron, sudo itself, and various PAM modules
		// read /etc/sudoers all the time; none of those are signal.
		return nil, nil
	}

	proc, err := s.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
	if err != nil {
		return nil, fmt.Errorf("get process pid %d: %w", p.PID, err)
	}
	if proc == nil {
		// Defensive: race against process materialisation. Same shape
		// as credential_keychain_dump / privilege_launchd_plist_write.
		return nil, nil
	}
	if r.allowed(proc.Path) {
		return nil, nil
	}

	return &detection.Finding{
		HostID:   evt.HostID,
		RuleID:   r.ID(),
		Severity: detection.SeverityHigh,
		Title:    "Sudoers tamper",
		Description: fmt.Sprintf(
			"%s opened %s for writing — sudo escalation surface (MITRE T1548.003)",
			proc.Path, p.Path,
		),
		ProcessID: proc.ID,
		EventIDs:  []string{evt.EventID},
	}, nil
}

func (r *SudoersTamper) allowed(writerPath string) bool {
	if r.AllowedWriters == nil {
		return false
	}
	_, ok := r.AllowedWriters[writerPath]
	return ok
}
