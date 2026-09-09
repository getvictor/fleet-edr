// Package sigmabind binds the Sigma evaluator to our event model: it maps Sigma's field names onto our event payloads, and refuses
// at load a rule that reads a field we do not supply (issue #760).
//
// It is deliberately separate from the sigma package, which knows nothing about our events. That package defines matching over an
// Event interface so its semantics can be tested against literal values; this one is the only place that knows what an exec payload
// looks like.
//
// The field set is what the corpus actually reads, measured rather than assumed. Across the 69 macOS SigmaHQ rules there are
// exactly five distinct detection fields: CommandLine (107 uses), Image (85), ParentImage (16 uses across 11 rules),
// TargetFilename (5) and OriginalFileName (1). Four are supplied. The one that is not is absent for a reason worth stating, because
// that absence is what the load-time check exists to report:
//
//   - ParentImage is supplied by the CALLER rather than read from the payload, which carries ppid but not the parent's path. The
//     graph knows it and this package does not know the graph, so NewExecEvent takes it as an argument (issue #771). An event
//     built without it reports the field absent, so a rule keyed on a parent declines rather than matching an unknown image.
//   - OriginalFileName is the name embedded in a Windows PE version resource. It has no macOS equivalent, so it is not a matter of
//     enrichment; inventing a value would misrepresent what we know.
package sigmabind

import (
	"fmt"
	"slices"
	"strings"

	"github.com/fleetdm/edr/server/rules/internal/export"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
)

// fieldExtractor returns the values an event carries for one Sigma field, and whether it carries the field at all. The values are
// built once when the event is decoded, so an extractor returns a stored slice rather than allocating per call.
type fieldExtractor func(*Event) ([]string, bool)

// taxonomy is the single source of truth for which Sigma fields we can supply, per event type. Both the load-time check and the
// per-event lookup read it, so a field cannot be matchable but unvalidated, or validated but unmatchable.
var taxonomy = map[string]map[string]fieldExtractor{
	// Sigma calls this category process_creation.
	"exec": {
		"Image": func(e *Event) ([]string, bool) { return e.image, e.image != nil },
		// Supplied by the caller from the process graph rather than read from the payload, which carries ppid but not the
		// parent's path. Standard Sigma taxonomy, so a rule reading it stays `portable: standard`.
		"ParentImage": func(e *Event) ([]string, bool) { return e.suppliedImageValues() },
		"CommandLine": func(e *Event) ([]string, bool) { return e.commandLine, e.commandLine != nil },
		// Computed from argv. Sigma carries no notion of argument position, and three of our detections turn on exactly that,
		// so the positional facts are precomputed and matched as fields. A rule using one is `portable: mapped`, not
		// `standard`: valid Sigma, but it needs a field only we supply. See argv.go.
		"Subcommand":       func(e *Event) ([]string, bool) { return e.subcommand, e.subcommand != nil },
		"CommandArguments": func(e *Event) ([]string, bool) { return e.commandArguments, e.commandArguments != nil },
		"EnvAssignments":   func(e *Event) ([]string, bool) { return e.envAssignments, e.envAssignments != nil },
	},
	// Sigma calls this category file_event.
	"open": {
		"TargetFilename": func(e *Event) ([]string, bool) { return e.targetFilename, e.targetFilename != nil },
		// The process that did the opening, supplied from the graph the way ParentImage is. Standard Sigma taxonomy: Image
		// means the acting process, whatever the event type.
		"Image": func(e *Event) ([]string, bool) { return e.suppliedImageValues() },
		// Nothing derived from the open's flags is supplied. Whether an open carried write access, and whether it carried a
		// content-changing flag, decide whether TargetFilename is supplied at all (see NewEvent); exposing them as fields is
		// what used to make a file rule `portable: mapped`, and #801 retired them.
	},
	// Sigma calls this category file_rename, and defines both of these fields, so the FIELDS a rule reads here are standard
	// taxonomy. Whether the RULE exports as portable is a separate question the exporter answers: one combining this category
	// with another cannot be routed by an external engine, because Sigma permits one logsource per rule.
	//
	// TargetFilename is the DESTINATION. That is the field a file rule already reads, and for a rename the destination is what
	// decides whether the file is now policy: promoting a scratch file into /etc/sudoers.d/evil is the escalation whether it
	// came from /tmp or from a sibling. SourceFilename is supplied alongside it so a rule can say where it came from, which is
	// the only thing separating an editor committing its own temp file from an attacker promoting one.
	"file_rename": {
		"TargetFilename": func(e *Event) ([]string, bool) { return e.targetFilename, e.targetFilename != nil },
		"SourceFilename": func(e *Event) ([]string, bool) { return e.sourceFilename, e.sourceFilename != nil },
		"Image":          func(e *Event) ([]string, bool) { return e.suppliedImageValues() },
	},
	// Destruction of a watched file. Both carry only the path they acted on, so both expose the same single field, and
	// TargetFilename is the right name for it: it is the file the event happened TO, which is what Sigma means by it.
	//
	// Sigma has a file_delete category and no truncate equivalent, so a rule reading file_delete stays standard taxonomy while
	// one reading file_truncate is ours. The exporter reports that difference rather than this table (#917).
	"file_truncate": {
		"TargetFilename": func(e *Event) ([]string, bool) { return e.targetFilename, e.targetFilename != nil },
		"Image":          func(e *Event) ([]string, bool) { return e.suppliedImageValues() },
	},
	"file_delete": {
		"TargetFilename": func(e *Event) ([]string, bool) { return e.targetFilename, e.targetFilename != nil },
		"Image":          func(e *Event) ([]string, bool) { return e.suppliedImageValues() },
	},
}

// EventTypeForCategory maps a Sigma logsource category onto the event type this package supplies fields for.
//
// The correspondence itself lives in the exporter, which owns the one editable definition; this narrows it to the categories we can
// actually populate. A category we could name but supply no fields for would pass a logsource check and then match nothing, so it
// is declined here rather than accepted and left inert.
func EventTypeForCategory(category string) (string, bool) {
	eventType, ok := export.EventTypeForCategory(category)
	if !ok {
		return "", false
	}
	if _, mapped := taxonomy[eventType]; !mapped {
		return "", false
	}
	return eventType, true
}

// SupportedFields returns the Sigma field names available for an event type, sorted. Empty for a type we do not map.
func SupportedFields(eventType string) []string {
	fields := taxonomy[eventType]
	out := make([]string, 0, len(fields))
	for name := range fields {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// Validate reports whether every field a rule reads can be supplied for the given event type.
//
// This is the load-time half of the contract: a rule naming a field we do not populate would otherwise compile, evaluate, and
// return false for that field on every event forever. That is indistinguishable from the adversary behaviour never occurring, so
// it must be an error at load rather than silence at match time.
func Validate(rule *sigma.Rule, eventType string) error {
	fields, ok := taxonomy[eventType]
	if !ok {
		return fmt.Errorf("event type %q has no Sigma field mapping; supported: %s", eventType, strings.Join(mappedEventTypes(), ", "))
	}
	var missing []string
	for _, name := range rule.Fields() {
		if _, ok := fields[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("rule reads field(s) %s which %s events do not supply; supported: %s",
			strings.Join(missing, ", "), eventType, strings.Join(SupportedFields(eventType), ", "))
	}
	return nil
}

// mappedEventTypes lists the event types with a field mapping, sorted, for error messages.
func mappedEventTypes() []string {
	out := make([]string, 0, len(taxonomy))
	for et := range taxonomy {
		out = append(out, et)
	}
	slices.Sort(out)
	return out
}
