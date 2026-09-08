package catalog

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
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
// The rule matches only the files sudo will actually PARSE. sudoers(5) says sudo
// reads each file in /etc/sudoers.d "skipping file names that end in '~' or
// contain a '.' character", so a name carrying a dot grants nothing no matter
// what is written into it. Verified on macOS 26.3 with three files of identical
// content differing only in name: zzdotless loaded, zz.dotted and zztilde~ did
// not.
//
// That narrowing fixed a live false positive (#933). The previous pattern
// matched any direct child, and one `visudo -f /etc/sudoers.d/<name>` writes
// `<name>.tmp` as a SIBLING inside the watched prefix, so every legitimate
// fragment edit raised a Critical escalation alert on a file sudo ignores. The
// old comment here claimed the opposite, that the client "never sees visudo's
// flow"; that holds for /etc/sudoers, whose temp file lands outside the watched
// set, and not for /etc/sudoers.d.
//
// Renames are read too, as of #917. The atomic-replace evasion (write a temp
// file, rename it onto a sudoers path) produced no CREATE and no WRITE on a
// watched path and was invisible. It is now caught on the rename's DESTINATION,
// which is what decides whether the file is policy. The two changes ship
// together deliberately: narrowing alone would have removed the detection that
// caught write-then-rename by accident, via the same over-broad pattern that
// caused the false positive.
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
		Summary: "Flags any non-allowlisted writer that changes /etc/sudoers or /etc/sudoers.d/*.",
		Description: "Detects an instant escalation primitive: writing to `/etc/sudoers` or any direct child of " +
			"`/etc/sudoers.d/`. A successful tamper grants future shell sessions arbitrary command execution as " +
			"root.\n\n" +
			"Unlike the persistence rules, this one deliberately does NOT key on Apple-signed platform binaries: " +
			"the canonical attacker tools for sudoers tampering ARE platform binaries (cp, tee, redirected shells, " +
			"even `sudo vi /etc/sudoers`), so a platform-binary filter would silence every realistic attack while " +
			"admitting almost nothing of value. Operators tune with a path-glob exclusion via the detection-config surface instead.\n\n" +
			"The rule reads renames as well as writes, so an attacker who writes a temp file and renames it onto a sudoers " +
			"path is caught at the moment the file becomes policy. It matches only the names sudo will actually parse: " +
			"sudoers(5) skips files in /etc/sudoers.d whose names contain a `.` or end in `~`, and a file sudo skips grants " +
			"nothing.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"open", "file_rename"},
		FalsePositives: []string{
			"Configuration-management agents (Ansible, Chef, Puppet, MDM-driven scripts) that drop a sudoers fragment under /etc/sudoers.d. Add a path-glob exclusion for their absolute writer paths.",
		},
		Limitations: []string{
			"Truncation and deletion are not detected: `: > /etc/sudoers` destroys the policy and emits nothing at all, because open(O_TRUNC) is a different kernel path from the CREATE/WRITE/RENAME this rule reads. Tracked as #934.",
			"A rename whose destination sudo will load fires whoever performed it, so an administrator committing a legitimate visudo edit of a /etc/sudoers.d/ fragment is reported alongside an attacker promoting a file into place. From the endpoint's view the two are the same operation on the same path, and the rule deliberately does not filter on platform-binary status (see the description). Operators tune with a path-glob exclusion on the writer.",
			"On an agent predating #301, which sends real open(2) flags, a writer that opens a sudoers file write-mode with no content-changing flag and then writes is no longer reported. #801 moved the lock-versus-modification decision into the field supplier, which does not distinguish writers, where the rule's own suppression named sudo alone. sudo's own lock is still not an alert, and no agent shipping today can produce either shape.",
		},
	}
}

// sudoersBytes is the substring fast-path filter applied to the raw JSON payload before json.Unmarshal. NOTIFY_OPEN fires on every
// file open in the kernel (thousands per second) and writes to sudoers happen on a stable host literally never. Skipping the JSON
// decode for opens that obviously don't qualify cuts the rule's CPU cost from "one unmarshal per open" to "one bytes.Contains per
// open". Both /etc/sudoers and /private/etc/sudoers contain the same magic substring, so a single check covers both forms.
//
// This depends on an invariant that is NOT visible from here, and that is worth naming because breaking it would silently disable
// the rule rather than fail anything. Swift's JSONEncoder escapes forward slashes, so the extension puts `"\/etc\/sudoers"` on
// the wire and the agent uploads those bytes unchanged. A raw scan for `/etc/sudoers` would miss every real event. What saves it
// is `event_queue.payload` being a MySQL JSON column: MySQL normalizes `\/` to `/` on storage, so the bytes this rule receives
// have already been unescaped. Verified against the running database, and pinned by
// TestSudoersTamper_PrefilterSurvivesTheExtensionsSlashEscaping.
//
// Changing that column to BLOB (which is the right choice for genuinely opaque bytes, and has been made elsewhere for that
// reason) would break this filter and every rule that scans raw payload bytes. Match on the escaped form too, or decode first.
var sudoersBytes = []byte("/etc/sudoers")

// SupportedExclusionMatchTypes lists the match types this rule consults: the sudoers writer path glob (issue #520).
func (r *SudoersTamper) SupportedExclusionMatchTypes() []api.ExclusionMatchType {
	return []api.ExclusionMatchType{api.ExclusionMatchPathGlob}
}

// sudoersDetection is the rule's logic, compiled from the detection block in its pack file.
var sudoersDetection = sync.OnceValue(func() *sigma.Rule { return detectionFor("sudoers_tamper") })

// Evaluate runs the rule with a scope of its own, which is the un-shared behaviour a direct caller gets. The engine calls
// EvaluateScoped instead, so the batch's Sigma-backed rules share one decode and one subject lookup per event.
func (r *SudoersTamper) Evaluate(
	ctx context.Context, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	return r.EvaluateScoped(ctx, &api.BatchScope{}, events, s)
}

// EvaluateScoped implements api.ScopedRule.
func (r *SudoersTamper) EvaluateScoped(
	ctx context.Context, scope *api.BatchScope, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	return evalEachScopedEvent(ctx, scope, events, s, r.evalEvent)
}

func (r *SudoersTamper) evalEvent(
	ctx context.Context, scope *api.BatchScope, evt api.Event, s api.GraphReader,
) (*api.Finding, error) {
	// A rename is read the same way a write is: the adapter supplies the DESTINATION as TargetFilename, so one detection asks
	// the right question of both. An open asks whether a policy file was written; a rename asks whether a file just became
	// policy, which is the escalation the write-then-rename evasion used to slip past entirely (#917).
	if evt.EventType != "open" && evt.EventType != "file_rename" {
		return nil, nil
	}
	// Checked before the adapter, and deliberately still a byte scan: it costs nothing and it keeps every open of some other path
	// from entering the shared memo, which would hold a decode for an event no rule goes on to read.
	if !bytes.Contains(evt.Payload, sudoersBytes) {
		return nil, nil
	}
	// The detection decides, including the sudo-lock suppression that used to sit after the subject lookup below. The subject's
	// image is resolved lazily inside the adapter, so a write to any other path never reads the graph.
	view := sigmaEvent(ctx, scope, evt, s)
	if view == nil {
		return nil, nil
	}
	se := view.Event
	matched := sudoersDetection().Matches(se)
	if resolveErr := se.ResolveErr(); resolveErr != nil {
		return nil, resolveErr
	}
	if !matched {
		return nil, nil
	}

	// The same process the detection matched on, not a second lookup of it: resolving again could return a different image if a
	// materialization commit landed in between, and the finding would then describe a writer other than the one the suppression
	// was decided against.
	proc, err := view.Subject()
	if err != nil {
		return nil, err
	}
	if proc == nil {
		// The writer's row never materialized within the grace window (resolveSubjectProcess raises the retryable
		// ErrProcessNotYetMaterialized while inside it), so there is no process to link the finding to.
		return nil, nil
	}

	if r.excluded(proc.Path, evt.HostID) {
		return nil, nil
	}

	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       r.DisplayName(),
		Description: sudoersDescription(evt.EventType, proc.Path, se),
		ProcessID:   proc.ID,
		EventIDs:    []string{evt.EventID},
	}, nil
}

// sudoersDescription writes the operator-facing sentence for a finding, and says what actually happened.
//
// It exists because the single "opened X for writing" wording became wrong the moment renames were read: a rename opens
// nothing, and live QA on the dev server surfaced an alert claiming `/bin/mv opened /etc/sudoers.d/evil for writing`. An
// analyst triaging that would look for a write that never occurred, and the distinction is the whole point of the detection:
// the file became live sudo policy without its contents ever being written on this host.
//
// The rename form names both paths, because where it came from is what an analyst needs next: a promotion out of /tmp reads
// very differently from an editor committing its own temp file.
func sudoersDescription(eventType, writerPath string, se *sigmabind.Event) string {
	target := firstField(se, "TargetFilename")
	if eventType == "file_rename" {
		return fmt.Sprintf(
			"%s renamed %s onto %s, making it sudo policy: escalation surface (MITRE T1548.003)",
			writerPath, firstField(se, "SourceFilename"), target,
		)
	}
	// The path the detection matched on, which is present exactly because it required write intent to get here.
	return fmt.Sprintf("%s opened %s for writing: sudo escalation surface (MITRE T1548.003)", writerPath, target)
}

func (r *SudoersTamper) excluded(writerPath, hostID string) bool {
	return r.Exclusions != nil && r.Exclusions.Excluded(r.ID(), api.ExclusionMatchPathGlob, writerPath, hostID)
}
