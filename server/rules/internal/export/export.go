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
	"strings"

	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"

	"github.com/fleetdm/edr/server/rules/api"
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
	Title          string    `yaml:"title"`
	ID             string    `yaml:"id"`
	Status         string    `yaml:"status"`
	Description    string    `yaml:"description"`
	Author         string    `yaml:"author"`
	Level          string    `yaml:"level"`
	Tags           []string  `yaml:"tags,omitempty"`
	Logsource      logsource `yaml:"logsource"`
	FalsePositives []string  `yaml:"falsepositives,omitempty"`
	Engine         engine    `yaml:"x-engine"`
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

// sigmaProduct maps our platform values onto Sigma's product vocabulary. Sigma says `macos` where Go says `darwin`.
var sigmaProduct = map[api.Platform]string{
	api.PlatformDarwin:  "macos",
	api.PlatformWindows: "windows",
	api.PlatformLinux:   "linux",
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
func Rule(md api.RuleMetadata, params *yaml.Node) ([]byte, error) {
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
	if md.Algorithm == "" {
		return nil, fmt.Errorf("export: rule %s names no algorithm", md.ID)
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
		FalsePositives: md.Doc.FalsePositives,
		Engine: engine{
			RuleID:          md.ID,
			Type:            "graph",
			Portable:        "none",
			PortabilityNote: portabilityNote,
			EventTypes:      md.Doc.EventTypes,
			Algorithm:       md.Algorithm,
			Params:          params,
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

// portabilityNote is the same for every Phase 1 export, because the reason is the same for every rule: the logic is Go. It is
// written out per file rather than left implicit so a reader of one file in isolation learns why it will not run elsewhere.
const portabilityNote = "The rule's logic is a Go implementation named by x-engine.algorithm, not a declarative detection block, " +
	"so there is nothing here for another engine to evaluate. Rules whose logic can be expressed in Sigma are being converted " +
	"separately; until a rule's logic lives in its file, this stays the honest answer."

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
	"# Everything here is regenerated from the rule's Go documentation EXCEPT x-engine.params, which the rules read at boot and\n" +
	"# which is therefore authored by hand: regeneration re-emits an existing params block verbatim, comments included.\n" +
	"# Run `task docs:rule-pack` after changing a rule's documentation or metadata.\n"

// File renders one detection as it appears in the committed pack: the rule document behind the generated-file header.
func File(md api.RuleMetadata, params *yaml.Node) ([]byte, error) {
	body, err := Rule(md, params)
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
func Pack(rules []api.RuleMetadata, paramsFor func(string) *yaml.Node) (map[string][]byte, error) {
	out := make(map[string][]byte, len(rules))
	for _, md := range rules {
		body, err := File(md, paramsFor(md.ID))
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
