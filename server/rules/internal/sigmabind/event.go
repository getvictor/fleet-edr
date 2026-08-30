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
}

// execPayload is the subset of an exec event this package reads. Deliberately partial: the taxonomy supplies two fields, so
// decoding the rest (code signing, hashes, pid generation) would cost allocation per event for values nothing here reads.
type execPayload struct {
	Path string   `json:"path"`
	Args []string `json:"args"`
}

// openPayload is the subset of a file-open event this package reads.
type openPayload struct {
	Path string `json:"path"`
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
	case "open":
		var p openPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return nil, fmt.Errorf("decode open payload for event %q: %w", ev.EventID, err)
		}
		e.targetFilename = presentString(p.Path)
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
// Sigma distinguishes a field that is missing (`Field: null`) from one present but empty (`Field: ”`), and this collapses the two
// for an empty path. That is deliberate: `path` is required by the event schema for both types we map, so an empty one means a
// malformed event rather than a process whose executable path is genuinely the empty string. Reporting it as present-and-empty
// would let a rule written as `Image: ”` match every malformed event, which is a worse answer than reporting nothing.
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
