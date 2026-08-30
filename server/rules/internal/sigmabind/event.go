package sigmabind

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
)

// Event implements sigma.Event. Asserted at compile time so a change to either side is a build failure rather than a rule that
// silently stops being evaluable.
var _ sigma.Event = (*Event)(nil)

// Event adapts one of our events to the sigma.Event interface.
//
// Construct it ONCE per event and evaluate every rule against that one instance. The payload is decoded and the field values are
// built here, so Field is then a map lookup returning a stored slice and allocates nothing. Building one per rule instead would
// re-decode the same JSON for every rule in the catalog, which is the cost this shape exists to avoid.
type Event struct {
	eventType string

	// Values are pre-built as one-element slices because sigma.Event returns a slice and a nil slice is how "the event does not
	// carry this field" is spelled. Storing them avoids allocating a slice header on every field access.
	image          []string
	commandLine    []string
	targetFilename []string

	// An image the caller supplies rather than the payload carrying it, because the graph knows it and this package does not.
	// One slot serves both uses, since an event has at most one: an exec resolves its PARENT's image, an open resolves the image
	// of the process that did the opening. Which name the taxonomy exposes it under depends on the event type.
	suppliedImage []string
	// Resolved on first access rather than up front, so an event no rule asks about costs nothing. See NewExecEventLazy.
	resolveImage func() (string, error)
	resolveErr   error
	resolveDone  bool

	// Flag-derived facts about a file open, kept as separate fields because the rule reading them applies them separately: one
	// gates on write access, the other suppresses one specific writer's lock pattern.
	writeIntent  []string
	mutatingOpen []string

	// Computed from argv rather than copied from a payload field. See argv.go for why each exists.
	subcommand       []string
	commandArguments []string
	envAssignments   []string
}

// execPayload is the subset of an exec event this package reads. Deliberately partial: the taxonomy supplies five fields and all of
// them come from the path and the argument vector, so decoding the rest (code signing, hashes, pid generation) would cost
// allocation per event for values nothing here reads.
type execPayload struct {
	Path string   `json:"path"`
	Args []string `json:"args"`
}

// openPayload is the subset of a file-open event this package reads.
type openPayload struct {
	Path  string `json:"path"`
	Flags int    `json:"flags"`
}

// writeAccessMask selects the access mode from open(2) flags: bits 0 and 1 hold O_RDONLY=0, O_WRONLY=1, O_RDWR=2, so anything
// non-zero there means the descriptor can be written. Higher bits (O_CREAT, O_TRUNC, O_APPEND) do not affect the access mode.
//
// This mirrors the same test in the sudoers_tamper rule deliberately, and the duplication is time-boxed: #772 adds an explicit
// write-intent field to the event, at which point both derivations give way to reading it.
const writeAccessMask = 0x3

// mutatingOpenMask is O_TRUNC | O_APPEND | O_CREAT: the bits a writer that intends to change a file's CONTENT sets, as opposed to
// one that opens it write-mode only to take a lock. The sudoers rule uses it to suppress exactly that pattern from sudo itself.
const mutatingOpenMask = 0x400 | 0x8 | 0x200

// NewExecEvent is NewEvent for an exec event whose parent process the caller has already resolved.
//
// ParentImage is a standard Sigma field and 11 of the 69 macOS corpus rules read it, but it is not in the payload: an exec event
// carries ppid, not the parent's path. The graph knows it, and this package deliberately does not know the graph, so the caller
// resolves it and passes it in. That keeps matching testable against literal values, and it keeps the lookup where the retry
// semantics live: the pipeline materializes processes before it evaluates rules, and a parent that has not landed yet raises
// ErrProcessNotYetMaterialized so the batch is retried rather than the finding lost.
//
// Passing "" is the honest answer when the parent could not be resolved, and reports the field as absent rather than empty, so a
// rule keyed on a parent simply does not match rather than matching a process whose image we do not know.
func NewExecEvent(ev api.Event, parentImage string) (*Event, error) {
	e, err := NewEvent(ev)
	if err != nil {
		return nil, err
	}
	e.suppliedImage = presentString(parentImage)
	return e, nil
}

// NewOpenEventLazy is NewEvent for a file-open event whose opening process the caller will resolve on demand.
//
// An open event carries the pid that did the opening, not its path, for the same reason an exec carries ppid and not the parent's
// path: the graph knows it and this package does not. Deferred for the same reason too, since a detection reaches the subject only
// after the far cheaper target-filename test has already narrowed the events.
func NewOpenEventLazy(ev api.Event, resolveImage func() (string, error)) (*Event, error) {
	e, err := NewEvent(ev)
	if err != nil {
		return nil, err
	}
	e.resolveImage = resolveImage
	return e, nil
}

// NewExecEventLazy is NewExecEvent for a parent whose resolution is expensive enough to be worth deferring.
//
// Resolving the parent means reading the process graph, and a detection that reads ParentImage almost always reads something
// cheaper first: `Image` narrows to a handful of binaries before the parent matters at all. Sigma's conditions short-circuit, so a
// resolver passed here runs only if the rule actually reaches the field, which restores the prefilter a converted rule would
// otherwise have lost and keeps the common case free of a database read.
//
// The resolver runs at most once per event. Its error is recorded rather than returned, because Field cannot report one, so a
// caller that needs to distinguish "no parent" from "could not look one up" checks ParentErr after evaluating.
func NewExecEventLazy(ev api.Event, resolveParent func() (string, error)) (*Event, error) {
	e, err := NewEvent(ev)
	if err != nil {
		return nil, err
	}
	e.resolveImage = resolveParent
	return e, nil
}

// ResolveErr reports a failure from the lazy image resolver, or nil when it succeeded or was never reached.
//
// A rule checks this AFTER evaluating: a resolver that failed leaves its field absent, which at match time is indistinguishable
// from a process that genuinely has no parent or could not be identified, and the two deserve different handling.
func (e *Event) ResolveErr() error { return e.resolveErr }

// suppliedImageValues returns the caller-supplied image, resolving it on first access and at most once per event.
func (e *Event) suppliedImageValues() ([]string, bool) {
	if e.resolveImage != nil && !e.resolveDone {
		e.resolveDone = true
		path, err := e.resolveImage()
		e.resolveErr = err
		if err == nil {
			e.suppliedImage = presentString(path)
		}
	}
	return e.suppliedImage, e.suppliedImage != nil
}

// NewEvent decodes an event into the Sigma fields it can supply.
//
// An event whose type has no mapping is not an error: it yields an Event that supplies no fields, because the caller may be
// evaluating a batch that mixes types and a rule only ever runs against the type its logsource names. A payload that does not
// parse IS an error, since that is a malformed event rather than an uninteresting one.
func NewEvent(ev api.Event) (*Event, error) {
	e := &Event{eventType: ev.EventType}
	switch ev.EventType {
	case "exec":
		var p execPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return nil, fmt.Errorf("decode exec payload for event %q: %w", ev.EventID, err)
		}
		e.image = presentString(p.Path)
		e.commandLine = commandLine(p.Args)
		e.subcommand = presentString(subcommand(p.Args))
		e.commandArguments = commandArguments(p.Args)
		e.envAssignments = envAssignments(p.Path, p.Args)
	case "open":
		var p openPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return nil, fmt.Errorf("decode open payload for event %q: %w", ev.EventID, err)
		}
		// Sigma's file_event category means file creation or modification (it is Sysmon's FileCreate), not "a file was opened".
		// Our open events include read-only opens, which are routine: the sudoers_tamper rule drops them for exactly this reason,
		// noting that cron, sudo itself and various PAM modules read /etc/sudoers constantly. Exposing TargetFilename for those
		// would import that noise into every file_event rule we adopt, as false positives rather than as a visible error.
		if p.Flags&writeAccessMask != 0 {
			e.targetFilename = presentString(p.Path)
		}
		e.writeIntent = presentBool(p.Flags&writeAccessMask != 0)
		e.mutatingOpen = presentBool(p.Flags&mutatingOpenMask != 0)
	}
	return e, nil
}

// Field implements sigma.Event.
func (e *Event) Field(name string) ([]string, bool) {
	extract, ok := taxonomy[e.eventType][name]
	if !ok {
		return nil, false
	}
	return extract(e)
}

// EventType returns the event type this adapter was built from.
func (e *Event) EventType() string { return e.eventType }

// presentString wraps a value for storage, treating the empty string as absent.
//
// Sigma distinguishes a field that is missing (`Field: null`) from one present but empty (`Field: ""`), and this collapses the two
// for an empty path. That is deliberate, and measured: of 650,565 real exec events, 18 carry an empty path and every one of them is
// a `snapshot: true` event, the synthetic exec the extension emits at start-up to materialise a process that already existed and
// whose path it could not recover. Those are legitimate events with a genuinely unknown image, not corrupt ones, so erroring on
// them would turn a known capture limitation into a recurring failure. Reporting the field present-and-empty would be worse still:
// a rule written `Image: ""` would then match every one of them.
func presentString(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

// commandLine renders argv as Sigma's CommandLine: the arguments joined by single spaces.
//
// argv[0] is included as the process reported it, which is what the corpus expects. Across the 69 macOS rules, none of the 203
// CommandLine match values contains a path separator: they are flags and tokens (' -d ', ' dump-keychain ', '--download '), so
// rewriting argv[0] to the resolved executable path would serve no rule and would differ from what the process was actually
// invoked with. Image already carries the resolved path for rules that want it.
//
// Sharp edge worth knowing: many corpus values are written with a space on both sides (' -d '), and a joined argv has no trailing
// separator, so such a value does not match a flag that appears last. That is a property of how those rules are written against
// Windows command lines rather than something this mapping can fix; appending a trailing space would break every |endswith.
//
// An exec with no arguments yields no CommandLine at all rather than an empty string, so a rule written as `CommandLine: null` (the
// corpus does contain one) matches it, which is what its author intended.
func commandLine(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	return []string{strings.Join(args, " ")}
}

// presentBool renders a boolean field the way Sigma matches one: as the text a rule writes, `true` or `false`. Always present, since
// a flag that is not set is a real answer rather than a missing one, unlike a path we could not resolve.
func presentBool(v bool) []string {
	if v {
		return []string{"true"}
	}
	return []string{"false"}
}
