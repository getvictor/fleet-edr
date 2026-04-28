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

// Doc surfaces the operator-facing description in /api/v1/admin/rules and
// the generated docs/detection-rules.md.
func (r *SudoersTamper) Doc() detection.Documentation {
	return detection.Documentation{
		Title:   "Sudoers tamper (write to /etc/sudoers or /etc/sudoers.d/*)",
		Summary: "Flags any non-allowlisted writer that opens /etc/sudoers or /etc/sudoers.d/* in write mode.",
		Description: "Detects an instant escalation primitive: writing to `/etc/sudoers` or any direct child of " +
			"`/etc/sudoers.d/`. A successful tamper grants future shell sessions arbitrary command execution as " +
			"root.\n\n" +
			"Unlike the persistence rules, this one deliberately does NOT key on Apple-signed platform binaries — " +
			"the canonical attacker tools for sudoers tampering ARE platform binaries (cp, tee, redirected shells, " +
			"even `sudo vi /etc/sudoers`), so a platform-binary filter would silence every realistic attack while " +
			"admitting almost nothing of value. Operators tune via EDR_SUDOERS_WRITER_ALLOWLIST instead.\n\n" +
			"`visudo` and `sudoedit` use atomic-rename semantics and never open /etc/sudoers in write mode, so the " +
			"rule does not see them at all.",
		Severity:   detection.SeverityHigh,
		EventTypes: []string{"open"},
		FalsePositives: []string{
			"Configuration-management agents (Ansible, Chef, Puppet, MDM-driven scripts) that drop a sudoers fragment under /etc/sudoers.d. Allowlist their absolute writer paths.",
		},
		Limitations: []string{
			"Atomic-rename writes (write a temp file, rename onto /etc/sudoers) are missed: ESF NOTIFY_OPEN doesn't fire on rename, and the extension does not subscribe to NOTIFY_RENAME today. Tracked as future work.",
		},
		Config: []detection.ConfigKnob{
			{
				EnvVar:      "EDR_SUDOERS_WRITER_ALLOWLIST",
				Type:        "csv-paths",
				Default:     "",
				Description: "Comma-separated absolute writer-process paths to silently accept (e.g. `/usr/local/bin/ansible`).",
			},
		},
	}
}

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

// O_TRUNC (0x400) | O_APPEND (0x8) | O_CREAT (0x200) — the bits an
// attacker who actually wants to mutate /etc/sudoers reaches for in
// the common case (cp / tee / shell `>` / shell `>>` / dd / vi-direct-
// save all set at least one of these three). macOS sudo opens
// /etc/sudoers with O_WRONLY (sometimes plus O_NONBLOCK or O_CLOEXEC)
// to take a LOCK_EX flock for serialised reads — write-mode by access,
// but no intent to modify content. The intent-mask check below
// suppresses sudo's flock pattern; we scope that suppression to
// `/usr/bin/sudo` specifically (see evalEvent) so a non-sudo writer
// using bare O_WRONLY still fires.
//
// Known limitation: a custom binary that opens /etc/sudoers with
// only O_WRONLY (no O_TRUNC/O_APPEND/O_CREAT) and writes a NOPASSWD
// entry from offset 0 is sufficient to plant the escalation, and
// neither the intent-mask gate (because the writer isn't sudo) nor
// the existing rename gap closes on it. Correlating on
// NOTIFY_WRITE / NOTIFY_CLOSE_MODIFIED instead of inferring intent
// from open(2) flags is the real fix; tracked for Phase 8 alongside
// the rename limitation noted above.
const sudoersWriteIntentMask = 0x400 | 0x8 | 0x200

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

	// Narrow the intent-mask suppression to /usr/bin/sudo specifically. sudo
	// is the one writer we know opens with O_WRONLY-only as part of its
	// LOCK_EX flock pattern (never actually writes); any other writer
	// reaching write-mode against /etc/sudoers stays on the unhappy path
	// even when no intent bit is set, so a custom binary doing
	// open(O_WRONLY) → write() at offset 0 still alerts. (The known-gap
	// note up at the top of the file describes the residual case where
	// the writer IS sudo but is doing something other than flocking.)
	if proc.Path == "/usr/bin/sudo" && p.Flags&sudoersWriteIntentMask == 0 {
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
