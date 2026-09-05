package catalog

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"

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
	// author is the upstream rule's own author field, carried so the operator-facing reference can credit them. The corpus is
	// licensed under DRL 1.1 and the bytes we distribute are unmodified, so attribution travels with the rule itself; this is what
	// lets it travel into our documentation about the rule as well.
	author string

	// references are the upstream rule's own citations, shown beside the attribution so provenance is one story rather than a
	// name with no way to check it.
	references []string

	// source is the vendored file's bytes, verbatim. Kept so an operator exporting this rule gets the upstream rule they can diff
	// against SigmaHQ, rather than a re-rendering of it in this project's format. See VendoredSource.
	source []byte

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
		References:     r.references,
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
	// Author is the upstream rule's attribution, carried into the operator-facing reference (DRL 1.1).
	Author string `yaml:"author"`
	// References are the upstream rule's own citations, carried through so an operator can read what the detection was written
	// from. All 69 files in the vendored corpus carry at least one.
	References []string `yaml:"references"`
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
		if !d.IsDir() && IsCorpusFile(p) {
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
// checkStemLengths refuses any filename whose stem cannot be stored as a rule identifier, before a single file is parsed.
//
// A preflight rather than a per-file check, because the per-file position made the refusal conditional on the file being otherwise
// valid: a rule using an unsupported field is a SOFT rejection, recorded and skipped, and an over-long name reached that exit
// first. The identifier here is an upstream filename, so this is the path a corpus re-sync introduces the problem through.
func checkStemLengths(names []string) error {
	for _, name := range names {
		id := strings.TrimSuffix(path.Base(name), path.Ext(name))
		if err := checkRuleIDLength(name, id); err != nil {
			return err
		}
		if !ruleIDCharset.MatchString(id) {
			return fmt.Errorf("%s: rule id %q may contain only letters, digits, underscore and hyphen", name, id)
		}
	}
	return nil
}

// ruleIDCharset is what a rule identifier may contain, and restricting it is what makes identity DECIDABLE rather than
// approximated.
//
// The id is stored in columns collated utf8mb4_0900_ai_ci, so MySQL decides whether two ids are the same, and that collation is
// accent-insensitive as well as case-insensitive: "naive_rule" and "naïve_rule" are one value to it. Reproducing that judgement in
// Go means reproducing a UCA collation, and the obvious approximations do not: strings.ToLower handles case and leaves accents
// alone, while NFD-and-strip-marks handles accents but still misses expansions such as the one that makes ss and the sharp s
// equal. An approximation here fails in the direction that matters, letting through a pair the database will then merge.
//
// So the charset is narrowed instead of the comparison being widened. Over this set, case is the ONLY way two ids can differ and
// still collate equal, which makes strings.ToLower an exact model of ai_ci rather than a hopeful one. Every rule in the vendored
// corpus already conforms, and a rule identifier has no need of anything outside it.
var ruleIDCharset = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func checkDuplicateStems(names []string) error {
	type claim struct{ file, id string }
	seen := make(map[string]claim, len(names))
	for _, name := range names {
		id := strings.TrimSuffix(path.Base(name), path.Ext(name))
		// Compared CASE-INSENSITIVELY, because Go is not what decides whether two rule ids are the same. The id is persisted in
		// detection_rule_settings and alerts, whose rule_id columns take the schema default collation (utf8mb4_0900_ai_ci), and
		// both carry a unique key over it: uk_detection_rule_settings_rule_scope and uk_alerts_dedup. So "Foo" and "foo" are one
		// value to MySQL however distinct they look here.
		//
		// ToLower is EXACT here rather than approximate, and only because ruleIDCharset ran first. That collation is also
		// accent-insensitive, which lowercasing does nothing about; over letters, digits, underscore and hyphen there are no
		// accents to be insensitive to, so case is the only way two ids can differ and still collate equal.
		//
		// Comparing them as exact Go strings therefore lets a corpus load two rules that the rest of the system cannot tell
		// apart: tuning one would tune the other, and their alerts would deduplicate into a single row. The corpus path column is
		// deliberately BINARY (see the rulecontent migration), so storage will happily hold both files, which is what makes this
		// reachable rather than theoretical once operators author content.
		folded := strings.ToLower(id)
		if prev, dup := seen[folded]; dup {
			if prev.id == id {
				return fmt.Errorf("%s: rule id %q is already claimed by %s; the later file would silently replace the earlier rule",
					name, id, prev.file)
			}
			return fmt.Errorf("%s: rule id %q collides with %q claimed by %s; rule ids are compared case-insensitively where they "+
				"are stored, so these two would share one row of per-rule settings and one alert dedup key", name, id, prev.id, prev.file)
		}
		seen[folded] = claim{file: name, id: id}
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
	// Length is a preflight for the same reason, and it was NOT one at first, which was a defect. parseImported returns soft
	// rejections for a rule using a field the binder cannot map, and those are recorded and skipped rather than failing the load.
	// So an over-long filename whose rule also used an unsupported field exited early as a soft rejection, and the hard refusal
	// this is meant to be never happened (issue #835 review). Checking the names up front means the refusal does not depend on
	// what else is wrong with the file.
	if err := checkStemLengths(names); err != nil {
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

// compileImportedDetection compiles one file's detection block, classifying every way it can fail.
//
// It returns an unmappableError when the rule is valid Sigma using a feature this evaluator has not built, which is a rule this
// sensor cannot RUN and joins the rejections so the rest of the corpus still loads. Every other failure is a defect in a file this
// repository vendored, and the whole point of checking the corpus in is that such a file fails the import loudly rather than
// disappearing into a rejection list nobody reads.
func compileImportedDetection(name string, detection yaml.Node) (*sigma.Rule, error) {
	if detection.IsZero() {
		return nil, fmt.Errorf("%s: no detection block, so nothing decides whether the rule fires", name)
	}
	var block map[string]any
	if err := detection.Decode(&block); err != nil {
		return nil, fmt.Errorf("%s: decode detection: %w", name, err)
	}
	compiled, err := sigma.Compile(block)
	switch {
	case err == nil:
		return compiled, nil
	case errors.Is(err, sigma.ErrUnsupported):
		// The compiler's own wording already leads with "unsupported Sigma feature", so restating it here would double it.
		return nil, unmappable("%s", err)
	default:
		return nil, fmt.Errorf("%s: compile detection: %w", name, err)
	}
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

	// Compiled BEFORE the applicability checks below, and the order is the point. Whether the detection block is intact is a fact
	// about the FILE, so a corrupted one we vendored must fail the import whether or not this sensor would ever have run the rule.
	// Applicability is a fact about this SENSOR, so it only decides which rejection reason to report when the rule is refusable
	// for more than one cause, and it reports the more useful one: "the agent does not collect this" tells a re-sync what to
	// build, where "this evaluator does not implement windash" would not.
	compiled, compileErr := compileImportedDetection(name, f.Detection)
	if _, refusable := errors.AsType[unmappableError](compileErr); compileErr != nil && !refusable {
		return nil, compileErr
	}

	// Two categories reach this import today, because that is what the macOS corpus contains: 67 process_creation rules and 2
	// file_event. Issue #763 also lists dns_query, network_connection and process_termination, and those stay unrouted on purpose:
	// SigmaHQ ships no macOS rule in any of them, so a mapping added now would be code no rule exercises and no test could reach
	// through this loader. They are routed when a rule needs them, which is also when the adapter for them can be verified.
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

	// Held until here: an unsupported feature is a rejection, and the applicability checks above report a better reason when they
	// also apply. Returned before Validate, which has no compiled rule to look at.
	if compileErr != nil {
		return nil, compileErr
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
		source:      raw,
		author:      f.Author,
		references:  f.References,
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
		// `level` is OPTIONAL in the Sigma specification, so a rule omitting it is valid Sigma rather than a broken file. We
		// cannot raise an alert without a severity, which makes it a rule this sensor cannot run: a rejection, not a hard error.
		return "", unmappable("no level, so the rule has no severity to raise an alert at")
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

// DefaultMode implements api.ModeDefaulter: an imported rule starts in monitor (issue #764).
//
// This project did not write these rules and no operator here has seen what they do on real fleets. Sixty-six unfamiliar rules
// arriving in alert mode is how a catalog loses trust in a week, and once trust is gone the alerts get muted wholesale, including
// the ones that were right. Monitor keeps each rule evaluating and records what it would have fired on, so promotion is a decision
// made against observed behaviour rather than against a rule's reputation upstream.
//
// This is the rule's DEFAULT, not a floor: an operator promoting one to alert overrides it, per the resolution order.
func (r *importedRule) DefaultMode() api.DetectionRuleMode { return api.DetectionRuleModeMonitor }

// Evaluate runs the compiled detection over the batch with a scope of its own, which is the un-shared behaviour a direct caller
// (the replay harness, a test) gets. The engine calls EvaluateScoped instead.
func (r *importedRule) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return r.EvaluateScoped(ctx, &api.BatchScope{}, events, s)
}

// EvaluateScoped runs the compiled detection over the batch, decoding each event through the scope so the corpus does not decode
// every event once per rule (issue #794).
func (r *importedRule) EvaluateScoped(
	ctx context.Context, scope *api.BatchScope, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	var findings []api.Finding
	var miss pendingMiss
	for _, evt := range events {
		if evt.EventType != r.eventTypes[0] {
			continue
		}
		finding, err := r.evalEvent(ctx, scope, evt, s)
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
func (r *importedRule) evalEvent(
	ctx context.Context, scope *api.BatchScope, evt api.Event, s api.GraphReader,
) (*api.Finding, error) {
	// A payload that does not decode, or that carries no pid, is malformed rather than uninteresting. One bad event must not
	// discard the findings the rest of the batch produced, so it is skipped rather than raised.
	view := sigmaEvent(ctx, scope, evt, s)
	if view == nil {
		return nil, nil
	}
	matched := r.detection.Matches(view.Event)
	if resolveErr := view.Event.ResolveErr(); resolveErr != nil {
		return nil, resolveErr
	}
	if !matched {
		return nil, nil
	}

	// The same process the detection matched against, not a second lookup of it.
	proc, err := view.Subject()
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

// importedCorpus is the vendored SigmaHQ macOS corpus, embedded so the rules ship with the binary rather than being read from a
// path an operator could move. The tree layout is upstream's own `<category>/` one, byte-for-byte, so a re-sync is a copy.
//
//go:embed imported
var importedCorpus embed.FS

// importedRules is the corpus loaded once. Memoized because loadImported walks 69 files and compiles a detection for each, which is
// start-up work, not per-call work.
var importedRules = sync.OnceValues(func() ([]api.Rule, []rejection) {
	rules, rejected, err := loadImported(importedCorpus, "imported")
	if err != nil {
		// A corpus this repository vendors either loads or the build is broken. Failing at start-up is the whole point of
		// checking it in: the alternative is a server that boots with a detection silently missing.
		panic(fmt.Sprintf("catalog: load imported corpus: %v", err))
	}
	return rules, rejected
})

// ImportedCorpusFS exposes the vendored corpus as an fs.FS, so a caller can seed storage from the copy embedded in this build.
//
// Exported because the corpus files still live in this package. ADR-0021 assigns rule content to `rulecontent`, and moving these
// files there is a follow-up: it is mechanical, it touches 55 files, and doing it in the same change as the carve would bury the
// carve. Until then the wiring runs through cmd/main, which passes this FS to rulecontent's seed, so rulecontent depends on
// nothing here and the supplier direction the ADR sets is preserved.
func ImportedCorpusFS() fs.FS { return importedCorpus }

// IsCorpusFile reports whether a path is rule content, as opposed to the packaging that ships alongside it.
//
// Exported for the same reason CorpusRoot is: the loader and anything that STORES the corpus have to agree on what counts, and a
// second copy of the rule would be a silent divergence. The vendored directory carries a README and a checksum manifest of the
// snapshot as checked in, and neither is rule content. Storing them would be worse than untidy: a manifest of hashes sitting
// beside content an operator can now edit invites someone to trust it after it has stopped being true.
func IsCorpusFile(p string) bool { return strings.EqualFold(path.Ext(p), ".yml") }

// CorpusRoot is the directory the vendored corpus lives under, and therefore the path prefix the stored documents carry.
//
// Exported because the seed and the loader have to agree on it: the seed records each document under the path it was walked from,
// and the loader is given the same root to read them back under. A literal in two places would be a silent mismatch that presents
// as an empty corpus.
const CorpusRoot = "imported"

// LoadCorpus parses rule documents from fsys under root into runnable rules, and reports the refusals alongside them.
//
// The injectable form of MustLoadImported, added so the corpus can come from storage rather than the binary (issue #766). Parsing
// is unchanged and deliberately so: this loader derives a rule's identity from its file stem and detects duplicate stems before
// anything is parsed, so a second loader written against stored documents would be a second set of those rules to keep in step.
//
// Returns an error rather than panicking, because a stored corpus is not a build artifact. A malformed vendored file is a mistake
// caught before check-in, which is why the embedded path may panic; a malformed STORED corpus is a runtime condition its caller has
// to decide about, and the decision (keep the previous good set) is not this function's to make.
func LoadCorpus(fsys fs.FS, root string) ([]api.Rule, []rejection, error) {
	return loadImported(fsys, root)
}

// MustLoadImported returns the imported rules, panicking if the vendored corpus does not load. Mirrors MustLoadPack and
// MustLoadDetections: a malformed file fails at start-up rather than on the first event.
func MustLoadImported() []api.Rule {
	rules, _ := importedRules()
	return rules
}

// ImportedRejections returns the rules the corpus carries that this sensor cannot run, with the reason for each.
//
// Exported for the generated rule reference, which lists them (via bootstrap.ImportedRejections, the seam tooling reaches the
// catalog through). A refusal is an expected outcome rather than an error, but it is one a reader should be able to see: without
// it, an upstream rule that is absent reads as an oversight instead of a decision.
func ImportedRejections() []rejection {
	_, rejected := importedRules()
	return rejected
}

// VendoredSource returns the upstream file a rule was imported from, verbatim, and whether the rule is a vendored one at all.
//
// It is the single place that answers "is this rule ours or upstream's", and both callers that need to know go through it. The
// exported rule pack skips vendored rules, because their declarative form already exists as the file this repository vendored and
// rendering a second one in this project's format would put two representations of one rule on disk. The per-rule export endpoint
// serves these bytes instead, so an operator exporting an imported rule gets the upstream rule they can diff against SigmaHQ
// rather than a re-rendering of it.
func VendoredSource(ruleID string) ([]byte, bool) {
	for _, r := range MustLoadImported() {
		imported, ok := r.(*importedRule)
		if ok && imported.id == ruleID {
			return imported.source, true
		}
	}
	return nil, false
}

// Origin implements the origin accessor the catalog surfaces mirror, naming the upstream project and the rule's own author.
func (r *importedRule) Origin() string {
	if r.author == "" {
		return "SigmaHQ"
	}
	return "SigmaHQ, by " + r.author
}
