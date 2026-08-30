// Package sigmabind binds the Sigma evaluator to our event model: it maps Sigma's field names onto our event payloads, and refuses
// at load a rule that reads a field we do not supply (issue #760).
//
// It is deliberately separate from the sigma package, which knows nothing about our events. That package defines matching over an
// Event interface so its semantics can be tested against literal values; this one is the only place that knows what an exec payload
// looks like.
//
// The field set is what the corpus actually reads, measured rather than assumed. Across the 69 macOS SigmaHQ rules there are
// exactly five distinct detection fields: CommandLine (107 uses), Image (85), ParentImage (16), TargetFilename (5) and
// OriginalFileName (1). Three of them are supplied here. The other two are absent for reasons worth stating, because their absence
// is what the load-time check exists to report:
//
//   - ParentImage needs the parent's executable path on an exec event. Our exec payload carries ppid but not the parent's path, so
//     supplying it needs the enrichment in #771. Its 16 uses are spread across 11 distinct rules, and those 11 fail to load,
//     loudly, which is the whole point: the alternative is a rule that loads and quietly never matches.
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
		"Image":       func(e *Event) ([]string, bool) { return e.image, e.image != nil },
		"CommandLine": func(e *Event) ([]string, bool) { return e.commandLine, e.commandLine != nil },
	},
	// Sigma calls this category file_event.
	"open": {
		"TargetFilename": func(e *Event) ([]string, bool) { return e.targetFilename, e.targetFilename != nil },
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
