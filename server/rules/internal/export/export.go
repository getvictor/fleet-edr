// Package export renders a registered detection as a declarative rule file (issue #757).
//
// The file is standard Sigma metadata plus one namespaced `x-engine` key holding what Sigma has no concept of. Phase 1 is
// deliberately pure output: nothing here is read back, no rule's behaviour depends on it, and a wrong choice costs a serialiser
// rewrite rather than an engine rewrite.
//
// # Why every export is type: graph today
//
// A rule is `type: sigma` only when its logic lives in the file's `detection:` block AND the engine evaluates it from there. All
// ten detections are Go implementations, so neither half is true yet and every export is honestly `type: graph` / `portable:
// none`. Emitting a hand-written `detection:` block that the engine never reads would be a claim about behaviour that nothing
// verifies, which is exactly how a draft of this format acquired an `interval_regularity_and_entropy` algorithm that no code
// implements. Converting the expressible rules, and with them the first real `type: sigma` files, is issue #761.
//
// # Why params are absent
//
// Rule constants are unexported Go values with no accessor on api.Rule. Adding accessors purely so the serialiser could read them
// back is work that issue #758 undoes when it moves those values into the files for real, so files gain `params` there rather
// than here.
package export

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
)

// idNamespace is the frozen UUID namespace rule ids are derived under. Sigma requires `id` to be a UUID and rejects a slug with
// SigmaIdentifierError, while our stable identifier is the snake_case rule id, so the file carries both: a uuid5 of the rule id
// here and the slug in x-engine.rule_id.
//
// The value is arbitrary and PERMANENT. It deliberately encodes nothing about the product or repository, because a rename would
// then silently change every rule's Sigma id, and an id that moves is worse than an ugly one: downstream tools key on it.
const idNamespace = "a53805f4-5268-4387-9a08-9dc59215332f"

// author is the attribution written into every exported rule. Imported community rules carry their own author, which the
// Detection Rule License obliges us to preserve wherever their matches are shown.
const author = "Fleet EDR"

// file is the exported document. Field order IS the emitted key order, so the Sigma half reads first and our extension last,
// matching how the format reference presents a rule and how every Sigma rule in the wild opens.
//
// That ordering is why this uses go.yaml.in/yaml/v3 rather than the sigs.k8s.io/yaml used elsewhere in the tree: the latter
// marshals via JSON and therefore emits keys alphabetically, which puts `author` first and `title` eighth. Deterministic, but
// alien to read in an artifact whose entire purpose is being read. Structs rather than maps throughout for the same reason: Go
// randomises map iteration, and a generated file that reorders itself between runs is unreviewable.
type file struct {
	Title          string     `yaml:"title"`
	ID             string     `yaml:"id"`
	Status         string     `yaml:"status"`
	Description    string     `yaml:"description"`
	Author         string     `yaml:"author"`
	Level          string     `yaml:"level"`
	Tags           []string   `yaml:"tags,omitempty"`
	Logsource      logsource  `yaml:"logsource"`
	Detection      *yaml.Node `yaml:"detection,omitempty"`
	FalsePositives []string   `yaml:"falsepositives,omitempty"`
	Engine         engine     `yaml:"x-engine"`
}

type logsource struct {
	Product  string `yaml:"product"`
	Category string `yaml:"category"`
}

type engine struct {
	RuleID          string     `yaml:"rule_id"`
	Type            string     `yaml:"type"`
	Portable        string     `yaml:"portable"`
	PortabilityNote string     `yaml:"portability_note"`
	EventTypes      []string   `yaml:"event_types,omitempty"`
	Algorithm       string     `yaml:"algorithm,omitempty"`
	Params          *yaml.Node `yaml:"params,omitempty"`
	Exclusions      []string   `yaml:"exclusions,omitempty"`
	Limitations     []string   `yaml:"limitations,omitempty"`
}

// sigmaCategory maps one of our event types onto the Sigma logsource category that means the same thing. Sigma allows exactly one
// category per rule, so a rule consuming several event types takes the category of its FIRST (the trigger), and the full set stays
// in x-engine.event_types where nothing is lost.
//
// An event type with no Sigma equivalent maps to itself. That is not a portability claim: those rules are `portable: none`
// regardless, and inventing a plausible-looking Sigma category for a Background Task Management registration would misrepresent
// the file to any tool that read it.
var sigmaCategory = map[string]string{
	"exec":            "process_creation",
	"open":            "file_event",
	"dns_query":       "dns_query",
	"network_connect": "network_connection",
}

// SigmaCategory reports the Sigma logsource category for one of our event types, and whether a genuine Sigma equivalent exists.
func SigmaCategory(eventType string) (string, bool) {
	c, ok := sigmaCategory[eventType]
	return c, ok
}

// eventTypeByCategory inverts sigmaCategory once, so the correspondence has exactly one editable definition. Writing a rule file
// and evaluating one read the same table from opposite ends; two hand-maintained tables would let us emit files under a category we
// then refuse to evaluate, which surfaces as rules that silently never run.
//
// Only entries with a genuine Sigma equivalent are inverted. sigmaCategory falls an unmapped event type through to its own name
// (see its comment), and inverting that would invent a Sigma category that does not exist.
var eventTypeByCategory = sync.OnceValue(func() map[string]string {
	out := make(map[string]string, len(sigmaCategory))
	for eventType, category := range sigmaCategory {
		out[category] = eventType
	}
	return out
})

// EventTypeForCategory reports which of our event types a Sigma logsource category names. It is the inverse of SigmaCategory, and
// is what lets a rule file declaring `category: process_creation` be evaluated against our exec events.
func EventTypeForCategory(category string) (string, bool) {
	et, ok := eventTypeByCategory()[category]
	return et, ok
}

// sigmaProduct maps our platform values onto Sigma's product vocabulary. Sigma says `macos` where Go says `darwin`.
var sigmaProduct = map[api.Platform]string{
	api.PlatformDarwin:  "macos",
	api.PlatformWindows: "windows",
	api.PlatformLinux:   "linux",
}

// Authored is the part of a rule file that is written by hand rather than generated, and which regeneration therefore re-emits
// verbatim, comments included.
//
// Params are the values a graph rule reads at boot (issue #758). Detection is the Sigma `detection:` block that IS a converted
// rule's logic (issue #761). Grouping them keeps Rule's signature stable as more of a rule moves into its file, which is the
// direction this epic runs in.
type Authored struct {
	Params    *yaml.Node
	Detection *yaml.Node
}

// computedFields are the Sigma field names this engine supplies itself rather than taking from Sigma's taxonomy. A detection
// reading any of them is `portable: mapped`: valid Sigma, but not evaluable by another engine without them.
//
// Owned here because portability is a property of the rendered FILE, and this package already owns the rest of the Sigma-format
// correspondence. server/rules/internal/sigmabind, which computes the values, drift-tests its taxonomy against this list.
// The value is why the field has to be computed, which differs by field and is what the rendered note reports. Fields sharing a
// reason render it once.
var computedFields = map[string]string{
	"Subcommand":       reasonFlattenedCommandLine,
	"CommandArguments": reasonFlattenedCommandLine,
	"EnvAssignments":   reasonFlattenedCommandLine,
	"WriteIntent":      reasonCompletedFileEvent,
	"MutatingOpen":     reasonCompletedFileEvent,
}

const (
	reasonFlattenedCommandLine = "it represents a command line as a single string, in which argument position is no longer recoverable"
	reasonCompletedFileEvent   = "it represents a file event as a completed creation or modification rather than an open with flags"
)

// IsComputedField reports whether a Sigma field name is one this engine supplies rather than one from Sigma's own taxonomy.
func IsComputedField(name string) bool { _, ok := computedFields[name]; return ok }

// classify derives x-engine.type and x-engine.portable from the rule itself, rather than taking either on trust.
//
// A rule with a detection block IS Sigma, and is portable to the extent that the fields it reads are Sigma's own: `standard` when
// every field comes from the taxonomy, `mapped` when any is one we compute. A rule without one is a Go implementation, so there is
// nothing in the file for another engine to run and `none` is the honest answer.
func classify(detection *yaml.Node) (kind, portable string, computed []string) {
	if detection == nil {
		return "graph", "none", nil
	}
	// The evaluator is asked which fields the block reads rather than this package walking the YAML itself. A second traversal of
	// the same shape would drift the moment the evaluator gained a search form, and the failure would be silent: a rule reading a
	// computed field would export as `portable: standard`, promising another engine it can run something it cannot.
	fields, err := detectionFieldNames(detection)
	if err != nil {
		// A block that does not compile cannot be classified. The caller refuses it a moment later with a better message; the
		// conservative answer here is the one that promises least.
		return "sigma", "mapped", nil
	}
	for _, field := range fields {
		if _, ok := computedFields[field]; ok {
			computed = append(computed, field)
		}
	}
	if len(computed) == 0 {
		return "sigma", "standard", nil
	}
	// Sorted so the rendered note is stable: detectionFieldNames follows the block's own order, which changes when a rule is edited.
	slices.Sort(computed)
	return "sigma", "mapped", computed
}

// detectionFieldNames compiles a detection block and asks it which fields it reads.
func detectionFieldNames(detection *yaml.Node) ([]string, error) {
	var block map[string]any
	if err := detection.Decode(&block); err != nil {
		return nil, err
	}
	rule, err := sigma.Compile(block)
	if err != nil {
		return nil, err
	}
	return rule.Fields(), nil
}

// RuleID derives the Sigma `id` for a rule id. Exported so tests and tooling can assert stability without duplicating the
// derivation, since the whole point of a uuid5 is that everyone computes the same answer.
func RuleID(ruleID string) string {
	return uuid.NewSHA1(uuid.MustParse(idNamespace), []byte(ruleID)).String()
}

// Rule renders one registered detection as a rule file.
//
// It returns an error rather than emitting a partial file when the metadata cannot produce a valid document. A rule file that is
// silently missing its level or its logsource is worse than no file: it looks authoritative and is not.
// params is the rule's verbatim params block, or nil when it declares none. It is passed in rather than derived because params
// are the one part of a rule file that is NOT generated from Go: the rules read them, so re-rendering them from parsed values
// would drop the comments that explain why each threshold is what it is.
func Rule(md api.RuleMetadata, authored Authored) ([]byte, error) {
	if md.ID == "" {
		return nil, errors.New("export: rule has no id")
	}
	if len(md.Platforms) == 0 {
		return nil, fmt.Errorf("export: rule %s declares no platform", md.ID)
	}
	if len(md.Doc.EventTypes) == 0 {
		return nil, fmt.Errorf("export: rule %s declares no event types", md.ID)
	}
	if md.Doc.Title == "" {
		return nil, fmt.Errorf("export: rule %s has no title", md.ID)
	}
	if md.Doc.Severity == "" {
		return nil, fmt.Errorf("export: rule %s has no severity", md.ID)
	}
	// An empty algorithm is the most dangerous omission of the three, because `omitempty` drops the key rather than emitting a
	// blank one: the file would look complete while missing the single thing that says what decides the rule.
	kind, portable, computed := classify(authored.Detection)
	if kind == "graph" && md.Algorithm == "" {
		return nil, fmt.Errorf("export: rule %s names no algorithm and has no detection block, so nothing says what decides it", md.ID)
	}
	product, ok := sigmaProduct[md.Platforms[0]]
	if !ok {
		return nil, fmt.Errorf("export: rule %s declares unknown platform %q", md.ID, md.Platforms[0])
	}

	category, mapped := sigmaCategory[md.Doc.EventTypes[0]]
	if !mapped {
		category = md.Doc.EventTypes[0]
	}

	doc := file{
		Title:          md.Doc.Title,
		ID:             RuleID(md.ID),
		Status:         "stable",
		Description:    description(md.Doc),
		Author:         author,
		Level:          md.Doc.Severity,
		Tags:           tags(md.Techniques),
		Logsource:      logsource{Product: product, Category: category},
		Detection:      authored.Detection,
		FalsePositives: md.Doc.FalsePositives,
		Engine: engine{
			RuleID:          md.ID,
			Type:            kind,
			Portable:        portable,
			PortabilityNote: portabilityNote(kind, portable, computed),
			EventTypes:      md.Doc.EventTypes,
			Algorithm:       algorithmFor(kind, md.Algorithm),
			Params:          authored.Params,
			Exclusions:      exclusions(md.SupportedExclusionMatchTypes),
			Limitations:     md.Doc.Limitations,
		},
	}
	return marshal(doc)
}

// marshal renders doc at two-space indent, which is what Sigma rules in the wild use and what every example in the format
// reference shows. yaml.v3 defaults to four, and a pack that indents differently from every rule an operator has seen elsewhere
// reads as not-quite-Sigma for no reason.
func marshal(doc file) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("close encoder: %w", err)
	}
	return buf.Bytes(), nil
}

// portabilityNote explains, in the file itself, why a rule will or will not run in another engine. Written out per file rather than
// left implicit so a reader of one rule in isolation learns the reason without going looking for it.
func portabilityNote(kind, portable string, computed []string) string {
	switch {
	case kind != "sigma":
		return "The rule's logic is a Go implementation named by x-engine.algorithm, not a declarative detection block, " +
			"so there is nothing here for another engine to evaluate. Rules whose logic can be expressed in Sigma are being " +
			"converted separately; until a rule's logic lives in its file, this stays the honest answer."
	case portable == "mapped":
		// The note names the fields rather than giving one canned reason for every mapped rule. The reasons genuinely differ:
		// the argv fields exist because Sigma flattens a command line into one string, the open-intent fields because Sigma
		// models a completed file modification rather than an open(2) with flags. A reader of one file in isolation is being
		// told whether they can run this rule, so the answer has to be about this rule.
		field, them := computedFieldPhrase(computed)
		return "The rule's logic is the detection block in this file. It is valid Sigma, but it reads " + field +
			", which this engine computes rather than taking from Sigma's own taxonomy, so another engine needs " + them +
			" supplied to evaluate the rule. Sigma has no equivalent because " + computedFieldReasons(computed) + "."
	default:
		return "The rule's logic is the detection block in this file and reads only fields from Sigma's own taxonomy, so any " +
			"Sigma-compatible engine can evaluate it as it stands."
	}
}

// computedFieldReasons renders the distinct reasons the given fields have to be computed, in the order the fields were reported so
// the sentence tracks the phrase that precedes it. Reciting every reason regardless of which fields a rule reads is what made the
// old canned note wrong: it told the reader of a file-event rule about argument vectors it never touches.
func computedFieldReasons(computed []string) string {
	var reasons []string
	for _, field := range computed {
		if reason, ok := computedFields[field]; ok && !slices.Contains(reasons, reason) {
			reasons = append(reasons, reason)
		}
	}
	switch len(reasons) {
	case 0:
		return "Sigma's taxonomy does not carry it"
	case 1:
		return reasons[0]
	default:
		return strings.Join(reasons[:len(reasons)-1], ", ") + " and " + reasons[len(reasons)-1]
	}
}

// computedFieldPhrase renders the computed field names as a noun phrase. A rule with no named fields reaches this only via the
// does-not-compile path in classify, which the caller refuses moments later, so the generic phrasing is the honest one there.
func computedFieldPhrase(computed []string) (phrase, pronoun string) {
	switch len(computed) {
	case 0:
		return "at least one field", "them"
	case 1:
		return "the field " + computed[0], "it"
	default:
		return "the fields " + strings.Join(computed[:len(computed)-1], ", ") + " and " + computed[len(computed)-1], "them"
	}
}

// description joins the one-line summary and the long-form description into Sigma's single description field. Sigma has no
// summary, and dropping either half would lose the part an operator actually reads: the summary is the elevator pitch the UI
// shows in a list, the description is the behavioural spec.
func description(d api.Documentation) string {
	switch {
	case d.Summary == "":
		return d.Description
	case d.Description == "":
		return d.Summary
	default:
		return d.Summary + "\n\n" + d.Description
	}
}

// tags renders MITRE technique ids in Sigma's tag vocabulary: lowercase, dot-separated, `attack.` prefixed. T1059.004 becomes
// attack.t1059.004.
func tags(techniques []string) []string {
	if len(techniques) == 0 {
		return nil
	}
	out := make([]string, 0, len(techniques))
	for _, t := range techniques {
		out = append(out, "attack."+strings.ToLower(t))
	}
	return out
}

// exclusions renders the match types the rule consults. Returns nil (an omitted key) rather than an empty list for a rule that
// consults none, so the file does not imply a tuning surface that is not there.
func exclusions(types []api.ExclusionMatchType) []string {
	if len(types) == 0 {
		return nil
	}
	out := make([]string, 0, len(types))
	for _, t := range types {
		out = append(out, string(t))
	}
	return out
}

// Header is prepended to every file in the committed pack, so someone who opens one in isolation, having never seen the
// generator, learns that hand-edits do not survive and where the content came from.
//
// It exempts x-engine.params explicitly, because the rules read those values: telling a contributor not to hand-edit the one
// block they must hand-edit is worse than no header at all.
//
// It belongs to the PACK, not to the rule document. GET /api/rules/{id}/export deliberately serves the document without it: that
// response is the operator's own copy to do as they like with, and telling them not to hand-edit their own download would be
// both wrong and confusing.
const Header = "# Generated by tools/gen-rule-pack from the registered rule catalog.\n" +
	"# Everything here is regenerated from the rule's Go documentation EXCEPT the detection block and x-engine.params. Those are\n" +
	"# the rule's own logic and the values it reads, so they are authored by hand and regeneration re-emits them verbatim,\n" +
	"# comments included.\n" +
	"# Run `task docs:rule-pack` after changing a rule's documentation or metadata.\n"

// File renders one detection as it appears in the committed pack: the rule document behind the generated-file header.
func File(md api.RuleMetadata, authored Authored) ([]byte, error) {
	body, err := Rule(md, authored)
	if err != nil {
		return nil, err
	}
	return append([]byte(Header), body...), nil
}

// Pack renders every supplied detection as its committed-pack file, keyed by rule id.
//
// It renders all of them before returning any, so a rule that cannot be rendered fails the whole pack. A partial pack is the
// failure mode worth avoiding: half of one looks like a real pack to the next reader and to CI's drift check, whereas an error
// with nothing written is unambiguous.
// paramsFor supplies each rule's verbatim params block. Passed in as a function so this package stays independent of the
// catalog that owns the pack; bootstrap, which imports both, wires them together.
func Pack(rules []api.RuleMetadata, authoredFor func(string) Authored) (map[string][]byte, error) {
	out := make(map[string][]byte, len(rules))
	for _, md := range rules {
		body, err := File(md, authoredFor(md.ID))
		if err != nil {
			return nil, fmt.Errorf("render %s: %w", md.ID, err)
		}
		out[md.ID] = body
	}
	return out, nil
}

// Prune removes rule files for rules that are no longer registered, leaving the shared-list definitions and any non-YAML file
// alone.
//
// It lives here rather than in the generator because CI runs ./server/... and not ./tools/..., so a guard tested only beside the
// generator is not tested at all. That is not hypothetical: the first regeneration after the shared lists were added deleted
// them, because they carry no rule id.
func Prune(dir string, pack map[string][]byte, keep string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var removed []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") || e.Name() == keep {
			continue
		}
		if _, registered := pack[strings.TrimSuffix(e.Name(), ".yml")]; registered {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove obsolete %s: %w", path, err)
		}
		removed = append(removed, path)
	}
	return removed, nil
}

// algorithmFor drops the algorithm from a Sigma rule. A converted rule's logic IS its detection block, so naming a Go evaluator
// beside it would point a reader at code that no longer decides anything.
func algorithmFor(kind, algorithm string) string {
	if kind == "sigma" {
		return ""
	}
	return algorithm
}
