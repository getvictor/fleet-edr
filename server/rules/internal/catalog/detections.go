package catalog

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"sync"

	"go.yaml.in/yaml/v3"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/export"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
)

// Detections are the Sigma `detection:` blocks converted rules carry in their pack files (issue #761).
//
// A converted rule's logic IS its file. Where a graph rule names a Go evaluator in x-engine.algorithm and reads tuning values from
// x-engine.params, a Sigma rule carries a detection block instead and has neither: the values that used to be params are the
// literals inside the block, which is where Sigma puts them and where a reader of the file expects to find them.
//
// Everything is compiled and checked when the pack loads, for the same reason params are: a detection that fails to compile, or
// that reads a field we do not supply, must fail at start-up rather than at first fire, on one host, as a detection that silently
// did not happen.

// detection is a compiled detection block plus the verbatim node the generator re-emits.
type detection struct {
	rule *sigma.Rule
	raw  *yaml.Node
}

// detectionFile is the part of a pack file this reads: the top-level detection block and the logsource that says which event type
// it applies to.
type detectionFile struct {
	Logsource struct {
		Category string `yaml:"category"`
	} `yaml:"logsource"`
	// A VALUE yaml.Node for the same reason params is: yaml.v3 captures a subtree only into the value type, and a *yaml.Node
	// decodes to an empty node that reads as "this rule declares no detection".
	Detection yaml.Node `yaml:"detection"`
	Engine    struct {
		RuleID    string `yaml:"rule_id"`
		Algorithm string `yaml:"algorithm"`
	} `yaml:"x-engine"`
}

var detections = sync.OnceValue(func() map[string]*detection {
	out, err := loadDetections(packFS)
	if err != nil {
		panic(fmt.Sprintf("catalog: loading rule detections: %v", err))
	}
	return out
})

// loadDetections compiles every detection block in the pack and checks it against the field taxonomy.
func loadDetections(fsys fs.FS) (map[string]*detection, error) {
	entries, err := fs.Glob(fsys, "pack/*.yml")
	if err != nil {
		return nil, fmt.Errorf("glob pack: %w", err)
	}
	sort.Strings(entries)

	out := make(map[string]*detection, len(entries))
	for _, name := range entries {
		if path.Base(name) == SharedListsFile {
			continue
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		var f detectionFile
		if err := yaml.Unmarshal(body, &f); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		// A graph rule has no detection block, which is not an error; it is the other half of the catalog.
		if f.Detection.Kind == 0 {
			continue
		}
		if f.Engine.RuleID == "" {
			return nil, fmt.Errorf("%s: x-engine.rule_id is empty", name)
		}
		// A rule says what decides it exactly once. Carrying both would leave a reader, and the exported file, unable to tell
		// which one actually runs, and would point maintenance at a Go evaluator the engine no longer consults.
		if f.Engine.Algorithm != "" {
			return nil, fmt.Errorf("%s: rule %q declares both a detection block and x-engine.algorithm %q; only one can decide it",
				name, f.Engine.RuleID, f.Engine.Algorithm)
		}
		d, err := compileDetection(&f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if _, dup := out[f.Engine.RuleID]; dup {
			return nil, fmt.Errorf("%s: duplicate rule_id %q; the later file would silently replace the earlier rule's detection",
				name, f.Engine.RuleID)
		}
		out[f.Engine.RuleID] = d
	}
	return out, nil
}

func compileDetection(f *detectionFile) (*detection, error) {
	var block map[string]any
	if err := f.Detection.Decode(&block); err != nil {
		return nil, fmt.Errorf("detection block is not a mapping: %w", err)
	}
	rule, err := sigma.Compile(block)
	if err != nil {
		return nil, fmt.Errorf("detection: %w", err)
	}
	// The logsource decides which taxonomy the rule's fields are checked against, so a detection reading an exec field under a
	// file_event category is refused here rather than matching nothing forever.
	eventType, ok := sigmabind.EventTypeForCategory(f.Logsource.Category)
	if !ok {
		return nil, fmt.Errorf("logsource category %q has no event type we supply fields for", f.Logsource.Category)
	}
	if err := sigmabind.Validate(rule, eventType); err != nil {
		return nil, fmt.Errorf("detection: %w", err)
	}
	return &detection{rule: rule, raw: &f.Detection}, nil
}

// detectionFor returns the compiled detection for a rule, panicking when the rule has none. Rules reach it through a memoised
// package-level accessor, so a missing block is a start-up failure rather than a silent non-match.
func detectionFor(ruleID string) *sigma.Rule {
	d, ok := detections()[ruleID]
	if !ok {
		panic(fmt.Sprintf("catalog: rule %q has no detection block; a converted rule's logic lives in its pack file", ruleID))
	}
	return d.rule
}

// AuthoredFor returns the hand-written parts of a rule's file, which regeneration re-emits verbatim.
func AuthoredFor(ruleID string) export.Authored {
	a := export.Authored{Params: ParamsNode(ruleID)}
	if d, ok := detections()[ruleID]; ok {
		a.Detection = d.raw
	}
	return a
}

// MustLoadDetections forces the detection blocks to compile, so a malformed one fails when the catalog is built.
func MustLoadDetections() { detections() }

// firstField returns the first value of a computed field, or "" when the event does not carry it.
//
// A converted rule reads back what its detection matched on so the alert can name it. Going through the same field the detection
// used, rather than re-deriving the value in Go, is what keeps the alert text and the match from drifting apart.
func firstField(se *sigmabind.Event, name string) string {
	values, ok := se.Field(name)
	if !ok || len(values) == 0 {
		return ""
	}
	return values[0]
}

// firstMatching returns the first value of a list-valued field satisfying pred, or "" when none does.
//
// Sigma matches a list-valued field when ANY element does, but a finding has to name WHICH one, and the evaluator does not report
// that. Re-finding it with the same predicate the detection used keeps the two in step.
func firstMatching(se *sigmabind.Event, name string, pred func(string) bool) string {
	values, ok := se.Field(name)
	if !ok {
		return ""
	}
	for _, v := range values {
		if pred(v) {
			return v
		}
	}
	return ""
}

// parentImageOf returns a resolver for an exec event's parent image, memoized so the graph is read at most once however many times
// it is called.
//
// Memoization is what lets several rules share one lookup: the resolver is bound into the shared adaptation of the event and each
// rule gets its own view of it (see sigmabatch.go). Without it, eleven corpus rules reading ParentImage would each issue their own
// pair of graph reads for the same event, which costs far more than the decode they also each repeated.
func parentImageOf(ctx context.Context, evt rulesapi.Event, gr rulesapi.GraphReader, childPID int) func() (string, error) {
	var (
		path     string
		err      error
		resolved bool
	)
	return func() (string, error) {
		if resolved {
			return path, err
		}
		resolved = true
		path, err = lookupParentImage(ctx, evt, gr, childPID)
		return path, err
	}
}

// lookupParentImage walks child to parent for one exec event.
//
// The parent is resolved at the CHILD'S FORK TIME, not the exec timestamp. A parent must be alive when it forks the child, but by
// the time the child execs it may have exited and had its pid reused, so the exec timestamp can select a different process
// entirely. This is the same bracket SuspiciousExec.lookupParentOf uses, and the reason it uses it.
func lookupParentImage(ctx context.Context, evt rulesapi.Event, gr rulesapi.GraphReader, childPID int) (string, error) {
	child, err := gr.GetProcessByPID(ctx, evt.HostID, childPID, evt.TimestampNs)
	if err != nil {
		return "", fmt.Errorf("get child pid %d: %w", childPID, err)
	}
	if child == nil || child.PPID <= 1 {
		return "", nil
	}
	parent, err := gr.GetProcessByPID(ctx, evt.HostID, child.PPID, child.ForkTimeNs)
	if err != nil {
		return "", fmt.Errorf("get parent pid %d: %w", child.PPID, err)
	}
	if parent == nil {
		return "", nil
	}
	return parent.Path, nil
}

// subjectImageOf adapts a subject-process accessor to the image resolver the Sigma adapter takes, so both read through one memo.
func subjectImageOf(subject func() (*rulesapi.Process, error)) func() (string, error) {
	return func() (string, error) {
		found, err := subject()
		if err != nil {
			return "", err
		}
		if found == nil {
			return "", nil
		}
		return found.Path, nil
	}
}

// subjectProcessOf returns an accessor for the process that did the opening, memoized so the graph is read at most once however
// many times it is called.
//
// The memo is not an optimisation alone. Resolving twice would let a materialization commit land between the reads and produce a
// finding about a different image than the one the detection matched, and sharing one accessor across the rules in a batch extends
// that guarantee across rules as well as within one.
func subjectProcessOf(
	ctx context.Context, evt rulesapi.Event, gr rulesapi.GraphReader, pid int,
) func() (*rulesapi.Process, error) {
	var (
		proc     *rulesapi.Process
		resolved bool
	)
	return func() (*rulesapi.Process, error) {
		if resolved {
			return proc, nil
		}
		found, err := resolveSubjectProcess(ctx, gr, evt, pid)
		if err != nil {
			return nil, err
		}
		proc, resolved = found, true
		return proc, nil
	}
}
