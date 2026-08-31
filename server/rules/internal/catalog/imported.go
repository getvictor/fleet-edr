package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/export"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
)

// importedRule is a detection whose every property comes from an upstream Sigma file, with no Go implementation behind it
// (issue #763).
//
// It exists so an upstream file needs NO modification to run here. A SigmaHQ rule carries no `x-engine` block, so anything this
// engine needs that Sigma does not define has to be derived rather than declared: the rule id from the filename, the platforms from
// the logsource product, the event types from its category. Every key we made mandatory would be a key that forks the corpus and
// turns a re-sync into a merge conflict.
//
// Measured against SigmaHQ's 69 macOS rules, two numbers that are worth keeping apart. 68 are FIELD-BINDABLE: they read only what
// this engine supplies (Image in 61, CommandLine in 59, ParentImage in 11, TargetFilename in 2) with modifiers it implements. Only
// 66 are RUNNABLE, because binding a rule's fields is not the same as the agent producing events for it to read.
//
// The three refusals: one reads OriginalFileName, a Sysmon field naming a PE's embedded original name that has no macOS
// equivalent; two are file_event rules watching paths the agent emits no open event for (see categoryIsInert).
type importedRule struct {
	id          string
	title       string
	description string
	severity    string
	techniques  []string
	platforms   []api.Platform
	eventTypes  []string
	falsePos    []string
	detection   *sigma.Rule
}

func (r *importedRule) ID() string                { return r.id }
func (r *importedRule) DisplayName() string       { return r.title }
func (r *importedRule) Techniques() []string      { return r.techniques }
func (r *importedRule) Platforms() []api.Platform { return r.platforms }

// SupportedExclusionMatchTypes is empty: an imported rule consults no exclusion, because nothing in its file names one. Operator
// tuning of an imported rule lives in detection_rule_settings, which is what keeps a re-sync from clobbering it.
func (r *importedRule) SupportedExclusionMatchTypes() []api.ExclusionMatchType { return nil }

func (r *importedRule) Doc() api.Documentation {
	return api.Documentation{
		Title:          r.title,
		Summary:        r.title,
		Description:    r.description,
		Severity:       r.severity,
		EventTypes:     r.eventTypes,
		FalsePositives: r.falsePos,
	}
}

// sigmaFile is the subset of an upstream Sigma file this engine reads. Every field is optional on the wire, because an upstream
// file is not obliged to carry anything we want; what is missing is either derived or refused by name.
type sigmaFile struct {
	Title         string   `yaml:"title"`
	Description   string   `yaml:"description"`
	Level         string   `yaml:"level"`
	Tags          []string `yaml:"tags"`
	FalsePositive []string `yaml:"falsepositives"`
	LogSource     struct {
		Category string `yaml:"category"`
		Product  string `yaml:"product"`
	} `yaml:"logsource"`
	Detection yaml.Node `yaml:"detection"`
}

// sigmaFilesUnder lists every *.yml in the tree under dir, sorted so a load is deterministic.
//
// Walked rather than globbed, because an upstream corpus is a directory TREE: SigmaHQ files live under
// rules/<product>/<category>/. Syncing that tree as it stands is the whole point, so the import has to read it as it stands.
//
// Recursion is also what makes loadImported's duplicate-id check reachable at all: two files in one directory cannot share a stem,
// but two directories can each hold a file of the same name, and those would resolve to one rule id.
func sigmaFilesUnder(fsys fs.FS, dir string) ([]string, error) {
	var names []string
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.EqualFold(path.Ext(p), ".yml") {
			names = append(names, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", dir, err)
	}
	sort.Strings(names)
	return names, nil
}

// checkDuplicateStems fails when two files resolve to one rule id, whatever directories they sit in.
//
// The id is the filename stem, so this is reachable only because the import walks a tree. Whichever file loaded second would
// otherwise win silently, and which rule an operator gets would depend on directory order.
func checkDuplicateStems(names []string) error {
	seen := make(map[string]string, len(names))
	for _, name := range names {
		id := strings.TrimSuffix(path.Base(name), path.Ext(name))
		if prev, dup := seen[id]; dup {
			return fmt.Errorf("%s: rule id %q is already claimed by %s; the later file would silently replace the earlier rule",
				name, id, prev)
		}
		seen[id] = name
	}
	return nil
}

// rejection is one upstream file this engine will not run, and why.
type rejection struct {
	File   string
	Reason string
}

// loadImported reads every *.yml under dir as an upstream Sigma rule, returning the rules it can run and the files it cannot.
//
// The two outcomes are deliberately different. A file this engine cannot MAP is expected: the corpus is written for a fleet of
// sensors, and SigmaHQ's macOS rules include one reading OriginalFileName, a Sysmon field naming a PE's embedded original name that
// has no macOS equivalent. Refusing the whole corpus over it would mean importing nothing. So it becomes a rejection, which the
// caller reports; it is never dropped silently, because a silently skipped rule is indistinguishable from one that never matches.
//
// A file that is unreadable, malformed, or claims an id another file already claimed is an error instead. Those say the import
// itself is broken rather than that one detection does not fit, and continuing past them would import a corpus that is not the one
// on disk.
func loadImported(fsys fs.FS, dir string) ([]api.Rule, []rejection, error) {
	names, err := sigmaFilesUnder(fsys, dir)
	if err != nil {
		return nil, nil, err
	}

	// Stems are checked BEFORE anything is parsed. Recording an id only after a successful parse would let a rejected file leave
	// its id unclaimed, so a second file with the same stem would import and the collision would go unreported.
	if err := checkDuplicateStems(names); err != nil {
		return nil, nil, err
	}

	out := make([]api.Rule, 0, len(names))
	var rejected []rejection
	for _, name := range names {
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", name, err)
		}
		rule, err := parseImported(name, raw)
		if err != nil {
			if cannotRun, ok := errors.AsType[unmappableError](err); ok {
				rejected = append(rejected, rejection{File: name, Reason: cannotRun.reason})
				continue
			}
			return nil, nil, err
		}
		out = append(out, rule)
	}
	return out, rejected, nil
}

// unmappableError marks a file this engine cannot run but the import should survive: the detection does not fit this sensor, rather
// than the file being broken.
type unmappableError struct{ reason string }

func (e unmappableError) Error() string { return e.reason }

// unmappable builds that error. The reason does NOT name the file: a rejection carries the file separately, and a caller printing
// both would say it twice.
func unmappable(format string, args ...any) error {
	return unmappableError{reason: fmt.Sprintf(format, args...)}
}

// parseImported turns one upstream file into a rule, or explains exactly why it cannot.
func parseImported(name string, raw []byte) (*importedRule, error) {
	var f sigmaFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if f.Title == "" {
		return nil, fmt.Errorf("%s: no title, so the rule has no name to show an operator", name)
	}

	eventType, ok := sigmabind.EventTypeForCategory(f.LogSource.Category)
	if !ok {
		return nil, unmappable("logsource category %q maps to no event type this agent collects", f.LogSource.Category)
	}
	if reason, inert := categoryIsInert(f.LogSource.Category); inert {
		return nil, unmappable("%s", reason)
	}
	platforms, err := platformsFor(f.LogSource.Product)
	if err != nil {
		return nil, err
	}
	severity, err := severityFor(f.Level)
	if err != nil {
		// Wrapped, not replaced: an unmappable level stays extractable as a rejection, while the file is named either way so a
		// corpus load says WHICH file is wrong rather than only that one is.
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	if f.Detection.IsZero() {
		return nil, fmt.Errorf("%s: no detection block, so nothing decides whether the rule fires", name)
	}
	var block map[string]any
	if err := f.Detection.Decode(&block); err != nil {
		return nil, fmt.Errorf("%s: decode detection: %w", name, err)
	}
	compiled, err := sigma.Compile(block)
	if err != nil {
		// A rejection, not a hard error. Valid Sigma can use a feature this evaluator does not implement (`windash`, a keyword
		// search, `timeframe`), and upstream is entitled to ship it: that is a rule this sensor cannot run, exactly like one
		// reading a field it does not collect. Failing the import would abandon the other sixty-odd rules over it.
		// Two different failures reach here and they are not the same event. Valid Sigma this evaluator does not implement is a
		// rule we cannot RUN, so it joins the rejections and the rest of the corpus still loads. A malformed detection block is a
		// defect in a file we vendored, and the whole point of checking the corpus in is that such a file fails loudly rather
		// than disappearing into a rejection list nobody reads.
		if errors.Is(err, sigma.ErrUnsupported) {
			// The compiler's own wording already leads with "unsupported Sigma feature", so restating it here would double it.
			return nil, unmappable("%s", err)
		}
		return nil, fmt.Errorf("%s: compile detection: %w", name, err)
	}
	if err := sigmabind.Validate(compiled, eventType); err != nil {
		return nil, unmappable("%s", err)
	}

	// The rule id is the filename stem, which is what lets an upstream file carry no x-engine block at all. SigmaHQ names its files
	// after the rule, and the stem is stable across a re-sync in a way the file's own UUID is not readable.
	id := strings.TrimSuffix(path.Base(name), path.Ext(name))
	if id == "" {
		// A file named exactly `.yml` is a valid directory entry and leaves nothing to identify the rule by. Findings, exclusions
		// and per-host settings all key on the id.
		return nil, fmt.Errorf("%s: no filename stem, so the rule has no identifier", name)
	}

	return &importedRule{
		id:          id,
		title:       f.Title,
		description: f.Description,
		severity:    severity,
		techniques:  techniquesFrom(f.Tags),
		platforms:   platforms,
		eventTypes:  []string{eventType},
		falsePos:    f.FalsePositive,
		detection:   compiled,
	}, nil
}

// categoryIsInert reports whether a category maps to an event type the agent emits too narrowly for the category's rules to fire.
//
// `file_event` is the case. It maps to `open`, but since #301 the agent's file client inverts target-path muting to observe ONLY
// /etc/sudoers and /etc/sudoers.d/ (see FileTamperSubscriber.watchedTargets), so an `open` event exists for no other path. An
// upstream file_event rule watching launch daemons or startup items would therefore load, register, and never once fire.
//
// That is exactly the outcome the refusal contract exists to prevent: a rule that can never match is indistinguishable from the
// behaviour never occurring. Refusing it says so, where importing it would look like coverage we do not have.
//
// This is a statement about the AGENT, not about Sigma. Widening the watched set, or subscribing to NOTIFY_WRITE more broadly,
// is what makes these rules importable; the refusal should be revisited then and not before.
//
// It is deliberately COARSER than the contract allows, and the gap is worth naming. A file_event rule watching /etc/sudoers WOULD
// run, and this refuses it along with the rest. Narrowing to path scope means reading each rule's TargetFilename values and
// comparing them against the agent's watched prefixes, which is guesswork the moment a rule matches on a fragment with |contains
// rather than a whole path. No macOS rule in the corpus targets those paths, so the finer check would today be machinery for a
// rule that does not exist. TestCategoryIsInert_RefusesEvenASudoersRule pins the false refusal so it is a known trade rather than
// a surprise, and it is the test to delete when a sudoers-watching rule appears.
func categoryIsInert(category string) (string, bool) {
	if category == "file_event" {
		return "category file_event maps to open, but this agent emits open only for /etc/sudoers paths (#301), " +
			"so a file_event rule watching anything else could never fire", true
	}
	return "", false
}

// platformsFor maps a Sigma logsource product onto the platforms this engine scopes rules by.
//
// It reads the same table the exporter writes with, inverted, rather than keeping a second copy. Two tables would let a platform
// added or renamed on one side make an exported file unimportable.
func platformsFor(product string) ([]api.Platform, error) {
	platform, ok := export.PlatformForProduct(product)
	if !ok {
		return nil, unmappable("logsource product %q is not a platform this engine targets", product)
	}
	return []api.Platform{platform}, nil
}

// severityFor maps a Sigma level onto the four severities an alert can carry.
//
// `informational` has no counterpart here and 7 of the 69 macOS rules use it. It becomes Low rather than being refused: the rule
// still detects something worth recording, and rejecting it would fork the corpus over a label.
func severityFor(level string) (string, error) {
	switch strings.ToLower(level) {
	case "critical":
		return api.SeverityCritical, nil
	case "high":
		return api.SeverityHigh, nil
	case "medium":
		return api.SeverityMedium, nil
	case "low", "informational":
		return api.SeverityLow, nil
	case "":
		return "", errors.New("no level, so the rule has no severity to raise an alert at")
	default:
		return "", unmappable("level %q is not one this engine can raise an alert at", level)
	}
}

// techniquesFrom pulls MITRE technique ids out of Sigma's attack tags. `attack.t1546.014` becomes `T1546.014`; tactic tags such as
// `attack.persistence` carry no technique id and are skipped.
func techniquesFrom(tags []string) []string {
	out := []string{}
	for _, tag := range tags {
		rest, found := strings.CutPrefix(strings.ToLower(tag), "attack.t")
		if !found || rest == "" || !isTechniqueID(rest) {
			continue
		}
		out = append(out, "T"+rest)
	}
	return out
}

// isTechniqueID reports whether s is a MITRE technique number: digits, optionally followed by a dot and more digits.
//
// Both sides of the dot must carry digits. `t.123` would otherwise export as the technique id `T.123`, which no ATT&CK Navigator
// layer can resolve, and a malformed tag is better dropped than turned into a mapping that looks real.
func isTechniqueID(s string) bool {
	base, sub, hasDot := strings.Cut(s, ".")
	if !allDigits(base) {
		return false
	}
	if !hasDot {
		return true
	}
	return allDigits(sub)
}

// allDigits reports whether s is one or more ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// adaptEvent builds the Sigma view of an event for this rule's event type, and returns the accessor for the subject process
// alongside it.
//
// An exec resolves its PARENT's image for ParentImage; an open resolves the image of the process that did the opening. Both are
// lazy, so a rule reading neither never touches the graph.
//
// The accessor is returned rather than discarded because for an open event it is the SAME lookup the finding needs, and issue #762
// established why that matters: resolving twice lets a materialization commit land between the reads, so a rule with a negated
// Image filter can match on an absent image and then attach the finding to the very process that should have suppressed it. The
// exec path has no such accessor to share, because there the two lookups are genuinely different rows: the parent's and the
// subject's.
func (r *importedRule) adaptEvent(
	ctx context.Context, evt api.Event, gr api.GraphReader, pid int,
) (*sigmabind.Event, func() (*api.Process, error), error) {
	if r.eventTypes[0] == "open" {
		return openEventWithSubject(ctx, evt, gr, pid)
	}
	ev, err := execEventWithParent(ctx, evt, gr, pid)
	return ev, func() (*api.Process, error) { return resolveSubjectProcess(ctx, gr, evt, pid) }, err
}

// subjectPID reads the pid the event is about. Every event type this engine maps carries one under the same key, which is what
// lets an imported rule stay generic: it never needs to know which payload shape it is looking at.
//
// This decode is paid PER RULE, and again inside the adapter, because the engine hands each rule the raw batch and offers no way to
// share an adapted event. With the corpus registered that is roughly two decodes per rule per event, which is the cost issue #794
// exists to remove by decoding once in the engine. It is not fixable from inside a rule, and #764 should not register the corpus
// before #794 lands.
func subjectPID(evt api.Event) (int, bool) {
	var p struct {
		PID *int `json:"pid"`
	}
	if err := json.Unmarshal(evt.Payload, &p); err != nil || p.PID == nil {
		return 0, false
	}
	return *p.PID, true
}

// Evaluate runs the compiled detection over the batch, in the same shape a converted rule uses.
func (r *importedRule) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	var findings []api.Finding
	var miss pendingMiss
	for _, evt := range events {
		if evt.EventType != r.eventTypes[0] {
			continue
		}
		finding, err := r.evalEvent(ctx, evt, s)
		if fatal := miss.absorb(err); fatal != nil {
			return nil, fatal
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings, miss.err
}

// evalEvent decides one event, returning the finding it produced or nil.
func (r *importedRule) evalEvent(ctx context.Context, evt api.Event, s api.GraphReader) (*api.Finding, error) {
	pid, ok := subjectPID(evt)
	if !ok {
		// A payload carrying no pid is malformed rather than uninteresting. One bad event must not discard the findings the rest
		// of the batch produced, so it is skipped rather than raised.
		return nil, nil
	}
	se, subject, err := r.adaptEvent(ctx, evt, s, pid)
	if err != nil {
		return nil, err
	}
	matched := r.detection.Matches(se)
	if resolveErr := se.ResolveErr(); resolveErr != nil {
		return nil, resolveErr
	}
	if !matched {
		return nil, nil
	}

	// The same process the detection matched against, not a second lookup of it.
	proc, err := subject()
	if err != nil {
		return nil, err
	}
	if proc == nil {
		// The subject's row never materialized within the grace window, so there is no process to link the finding to.
		return nil, nil
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.id,
		Severity:    r.severity,
		Title:       r.title,
		Description: fmt.Sprintf("%s matched the imported rule %q", proc.Path, r.title),
		ProcessID:   proc.ID,
		EventIDs:    []string{evt.EventID},
	}, nil
}
