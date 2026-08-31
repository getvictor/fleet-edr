package catalog

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
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

// sudoersBytes is the substring fast-path filter applied to the raw JSON payload before json.Unmarshal. NOTIFY_OPEN fires on every
// file open in the kernel (thousands per second) and writes to sudoers happen on a stable host literally never. Skipping the JSON
// decode for opens that obviously don't qualify cuts the rule's CPU cost from "one unmarshal per open" to "one bytes.Contains per
// open". Both /etc/sudoers and /private/etc/sudoers contain the same magic substring, so a single check covers both forms.
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
	if evt.EventType != "open" {
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
		HostID:   evt.HostID,
		RuleID:   r.ID(),
		Severity: api.SeverityHigh,
		Title:    r.DisplayName(),
		Description: fmt.Sprintf(
			"%s opened %s for writing: sudo escalation surface (MITRE T1548.003)",
			// The path the detection matched on, which is present exactly because it required write intent to get here.
			proc.Path, firstField(se, "TargetFilename"),
		),
		ProcessID: proc.ID,
		EventIDs:  []string{evt.EventID},
	}, nil
}

func (r *SudoersTamper) excluded(writerPath, hostID string) bool {
	return r.Exclusions != nil && r.Exclusions.Excluded(r.ID(), api.ExclusionMatchPathGlob, writerPath, hostID)
}
