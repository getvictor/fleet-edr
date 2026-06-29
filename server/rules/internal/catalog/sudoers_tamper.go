package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/fleetdm/edr/server/rules/api"
)

// SudoersTamper fires on a write-mode `open(2)` against `/etc/sudoers`
// or any direct child of `/etc/sudoers.d/`. Editing those files grants
// future shell sessions arbitrary command execution as root, so a
// successful tamper is an instant escalation primitive (T1548.003).
//
// The rule deliberately does NOT key on code-signing platform-binary
// status the way persistence_launchagent / privilege_launchd_plist_write
// do, because the canonical attacker tools for sudoers tampering are
// platform binaries themselves: `cp`, `tee`, shell redirection, even
// `sudo vi /etc/sudoers`. Filtering platform binaries would silence
// every realistic attack while admitting basically nothing else of
// interest. We fire on any unexcluded writer instead, and let
// operators tune with a path-glob exclusion via the detection-config surface.
//
// Collection (ADR-0008 / #301): these write-mode `open` events are no longer
// drawn from a broad NOTIFY_OPEN firehose. The extension watches /etc/sudoers
// + /etc/sudoers.d/* on a dedicated, target-path-mute-inverted Endpoint
// Security client (NOTIFY_CREATE + NOTIFY_WRITE only) and re-emits each as a
// write-mode `open` event, so this rule's match logic is unchanged while the
// host no longer forwards every file open.
//
// Why visudo doesn't need to be in the default allowlist: visudo writes
// to /etc/sudoers.tmp (or $TMPDIR) and atomically renames it onto
// /etc/sudoers, so the file-tamper client (which watches CREATE/WRITE on
// /etc/sudoers but deliberately NOT rename) never sees visudo's flow.
// Same is true for sudoedit. The rule only trips when something creates
// or writes /etc/sudoers* directly.
//
// Known limitation: an attacker with root could write a temp file and rename
// it onto /etc/sudoers without ever firing CREATE/WRITE on /etc/sudoers.
// Subscribing to NOTIFY_RENAME would catch that, but it would also fire on
// every legitimate visudo/sudoedit edit, so the atomic-replace gap is left
// documented (same class as the privilege_launchd_plist_write atomic-rename
// gap, which BTM registration now covers).
type SudoersTamper struct {
	// Exclusions is the per-host false-positive resolver. The rule silently accepts a write whose writer-process path matches an
	// exclusion (match type path_glob). Nil excludes nothing (the empty-config default): every direct write to sudoers fires.
	Exclusions api.ExclusionResolver
}

func (r *SudoersTamper) ID() string { return "sudoers_tamper" }

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519).
func (r *SudoersTamper) DisplayName() string { return "Sudoers tamper" }

// Techniques returns the MITRE ATT&CK IDs this rule covers: T1548.003
// (Abuse Elevation Control Mechanism: Sudo and Sudo Caching).
func (r *SudoersTamper) Techniques() []string { return []string{"T1548.003"} }

// Doc surfaces the operator-facing description in /api/rules and
// the generated docs/detection-rules.md.
func (r *SudoersTamper) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags any non-allowlisted writer that opens /etc/sudoers or /etc/sudoers.d/* in write mode.",
		Description: "Detects an instant escalation primitive: writing to `/etc/sudoers` or any direct child of " +
			"`/etc/sudoers.d/`. A successful tamper grants future shell sessions arbitrary command execution as " +
			"root.\n\n" +
			"Unlike the persistence rules, this one deliberately does NOT key on Apple-signed platform binaries: " +
			"the canonical attacker tools for sudoers tampering ARE platform binaries (cp, tee, redirected shells, " +
			"even `sudo vi /etc/sudoers`), so a platform-binary filter would silence every realistic attack while " +
			"admitting almost nothing of value. Operators tune with a path-glob exclusion via the detection-config surface instead.\n\n" +
			"`visudo` and `sudoedit` use atomic-rename semantics and never open /etc/sudoers in write mode, so the " +
			"rule does not see them at all.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"open"},
		FalsePositives: []string{
			"Configuration-management agents (Ansible, Chef, Puppet, MDM-driven scripts) that drop a sudoers fragment under /etc/sudoers.d. Add a path-glob exclusion for their absolute writer paths.",
		},
		Limitations: []string{
			"Atomic-rename writes (write a temp file, rename onto /etc/sudoers) are missed: ESF NOTIFY_OPEN doesn't fire on rename, and the extension does not subscribe to NOTIFY_RENAME today. Tracked as future work.",
		},
	}
}

// sudoersPath matches /etc/sudoers itself and any direct child of /etc/sudoers.d/. ESF reports both forms (/etc/... and
// /private/etc/... since /etc is a symlink); we accept either. Nested paths (/etc/sudoers.d/foo/bar) are excluded by `[^/]+` so the
// rule can't be lured by an attacker creating a same-named subdirectory somewhere unrelated.
var sudoersPath = regexp.MustCompile(`^(?:/private)?/etc/sudoers(?:\.d/[^/]+)?$`)

// sudoersBytes is the substring fast-path filter applied to the raw JSON payload before json.Unmarshal. NOTIFY_OPEN fires on every
// file open in the kernel (thousands per second) and writes to sudoers happen on a stable host literally never. Skipping the JSON
// decode for opens that obviously don't qualify cuts the rule's CPU cost from "one unmarshal per open" to "one bytes.Contains per
// open". Both /etc/sudoers and /private/etc/sudoers contain the same magic substring, so a single check covers both forms.
var sudoersBytes = []byte("/etc/sudoers")

// sudoersOpenPayload mirrors the open event shape we care about. Local to this rule: the sibling privilege_launchd_plist_write rule
// no longer consumes open events (it keys on BTM registration per ADR-0008), so there is no shared open-payload type to extract. The
// identical Evaluate fan-out is shared via evalEachEvent.
type sudoersOpenPayload struct {
	PID   int    `json:"pid"`
	Path  string `json:"path"`
	Flags int    `json:"flags"`
}

// Bits 0 and 1 of open(2) flags hold the access mode: O_RDONLY=0, O_WRONLY=1, O_RDWR=2. Anything non-zero in those two bits means the
// fd can be written. Higher bits (O_CREAT, O_TRUNC, O_APPEND, ...) don't affect the access mode.
const sudoersWriteAccessMask = 0x3

// O_TRUNC (0x400) | O_APPEND (0x8) | O_CREAT (0x200): the bits an
// attacker who actually wants to mutate /etc/sudoers reaches for in
// the common case (cp / tee / shell `>` / shell `>>` / dd / vi-direct-
// save all set at least one of these three). macOS sudo opens
// /etc/sudoers with O_WRONLY (sometimes plus O_NONBLOCK or O_CLOEXEC)
// to take a LOCK_EX flock for serialised reads: write-mode by access,
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
// from open(2) flags is the real fix; tracked alongside the rename
// limitation noted above.
const sudoersWriteIntentMask = 0x400 | 0x8 | 0x200

func (r *SudoersTamper) Evaluate(
	ctx context.Context, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	return evalEachEvent(ctx, events, s, r.evalEvent)
}

func (r *SudoersTamper) evalEvent(
	ctx context.Context, evt api.Event, s api.GraphReader,
) (*api.Finding, error) {
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

	// Narrow the intent-mask suppression to /usr/bin/sudo specifically. sudo is the one writer we know opens with O_WRONLY-only as part of
	// its LOCK_EX flock pattern (never actually writes); any other writer reaching write-mode against /etc/sudoers stays on the unhappy
	// path even when no intent bit is set, so a custom binary doing open(O_WRONLY) → write() at offset 0 still alerts. (The known-gap note
	// up at the top of the file describes the residual case where the writer IS sudo but is doing something other than flocking.)
	if proc.Path == "/usr/bin/sudo" && p.Flags&sudoersWriteIntentMask == 0 {
		return nil, nil
	}
	if r.excluded(proc.Path, evt.HostID) {
		return nil, nil
	}

	return &api.Finding{
		HostID:   evt.HostID,
		RuleID:   r.ID(),
		Severity: api.SeverityHigh,
		Title:    r.DisplayName(),
		Description: fmt.Sprintf(
			"%s opened %s for writing: sudo escalation surface (MITRE T1548.003)",
			proc.Path, p.Path,
		),
		ProcessID: proc.ID,
		EventIDs:  []string{evt.EventID},
	}, nil
}

func (r *SudoersTamper) excluded(writerPath, hostID string) bool {
	return r.Exclusions != nil && r.Exclusions.Excluded(r.ID(), api.ExclusionMatchPathGlob, writerPath, hostID)
}
