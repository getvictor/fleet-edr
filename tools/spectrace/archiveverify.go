package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// archivedRestatement is one archived change's MODIFIED entry for one requirement, with the folder it came from.
type archivedRestatement struct {
	change    string
	scenarios []string
	// text is the entry's prose as comparable logical lines, which is what a scenario heading cannot tell you: a restatement can
	// refine a requirement's normative wording, or one scenario's THEN clause, while listing exactly the scenario names the body
	// it replaces already had.
	text requirementText
}

// verifyArchive reports where the canonical tree disagrees with what the archived deltas say it should hold.
//
// This is the detection half of issue #901, and it exists because the prevention half is advice. `archive-order` prints an order,
// and an operator who archives in a different one gets no error from anything: `openspec validate --strict` passes on a
// requirement that lost half its text, and `check --strict` passes as long as whatever survived still has markers.
//
// Four shapes, each with its own function below: a scenario the last batch's restatements all listed that is not canonical, a
// canonical scenario none of them listed, prose in either of those directions, and a requirement an archived change retired that
// is still there. Prose was left out at first on the grounds that comparing wording would report formatting as loss, which was
// true of the obvious implementation and not of the one splitRequirementText does: see its comment for the measurements.
//
// What this CANNOT do is tell a loss from a legitimate retirement, and the reason is worth stating because it bounds the whole
// design: openspec stamps every folder in one batch with the same date, so within a batch the archive order is not recoverable
// from the tree, and "the last restatement wins" cannot be evaluated. A scenario a later change deliberately retired therefore
// looks the same here as one an out-of-order archive discarded.
//
// It also cannot tell two archive passes made on the SAME DAY apart, which review raised and which is the same limit seen from a
// different angle. Both passes' folders carry one date, so both are read as one batch and their restatements intersected; if the
// second pass restated a requirement more fully than the first, the part only it carried is not claimed and its loss would go
// unreported. That is a missed finding rather than a false one, which is the direction this file errs in everywhere, and the
// release checklist archives every pending change in a single pass (step 2), so the case needs a deliberate departure from the
// documented process to arise. The tree carries no finer signal than the date, so detecting it would mean passing the batch in.
//
// So this REPORTS and does not gate, and the checklist uses it as a before-and-after: run it, archive, run it again, and any line
// that is new is damage this archive did. That comparison needs no ordering and no baseline file, and it is the question a
// release engineer actually has.
func verifyArchive(archived map[string][]archivedRestatement, canonical map[string]map[string]struct{},
	lifecycle map[string]requirementLifecycle, text map[string]requirementText,
) []string {
	var losses []string
	// Every requirement an archived delta said anything about, not only the ones it restated: a retirement that did not take
	// effect is a finding, and the change that retired a requirement usually did not also restate it.
	for _, requirement := range requirementsTouched(archived, lifecycle) {
		entries := archived[requirement]
		have, stillCanonical := canonical[requirement]
		life := lifecycle[requirement]

		// A retirement excuses a requirement that is GONE, and the canonical tree is what says whether it took effect.
		//
		// Two earlier versions of this asked the archive folders instead, and both were wrong in the same way. Comparing folder
		// names is alphabetical order, which review caught: within a batch every folder carries one date, so the pending pair
		// `latch-dns-proxy-bypass` (restates) and `dns-proxy-no-bypass` (retires) would have read as a loss. Comparing DATES fixed
		// that and left the opposite hole: a retirement the archive did not end up applying still excused the requirement.
		//
		// Neither question needed asking. The end state answers both, and it answers a third the folders could not: a requirement
		// still in the tree that a change retired and nothing re-added is a retirement the archive dropped, which is as much a
		// silent archive defect as a lost scenario and is reported as one. Four requirements are in that state today, all retired
		// by `2026-06-02-add-application-control`, and none of them was ever the subject of an ADDED delta.
		//
		// "And nothing re-added" is the part review caught missing. A retirement is not the last word on a requirement: a later
		// change may add it back, legitimately, and then its presence is expected rather than damage.
		//
		// Which cuts both ways, and the second half is what review caught NEXT: a requirement retired and then re-added is an
		// ordinary requirement again, so it goes through the scenario checks below like any other. Skipping those on the mere
		// existence of a retirement, which is what this did, left a re-added requirement's later restatements unverified forever.
		if life.retiredLast() {
			// Gone as intended, or still here when it should not be. Either way the requirement's scenarios are not the question.
			if stillCanonical {
				losses = append(losses, requirement+"\n    retired by an archived change and still in the canonical spec")
			}
			continue
		}

		if len(entries) == 0 {
			continue
		}
		winner := lastBatchRestatement(entries)
		losses = append(losses, missingScenarios(requirement, winner, have)...)
		losses = append(losses, unretiredScenarios(requirement, winner, have)...)
		losses = append(losses, missingText(requirement, winner, text[requirement])...)
	}
	sort.Strings(losses)
	return losses
}

// textKeys is a restatement's prose as a SET of (scenario, line) pairs, where an empty scenario means the requirement's own body.
// A set rather than a list because the counting below is "how many restatements carried this", not "how many times it appears".
func textKeys(t requirementText) map[[2]string]struct{} {
	out := make(map[[2]string]struct{}, len(t.body))
	for _, line := range t.body {
		out[[2]string{"", line}] = struct{}{}
	}
	for scenario, lines := range t.scenarios {
		for _, line := range lines {
			out[[2]string{scenario, line}] = struct{}{}
		}
	}
	return out
}

func appendText(t *requirementText, key [2]string) {
	if key[0] == "" {
		t.body = append(t.body, key[1])
		return
	}
	t.scenarios[key[0]] = append(t.scenarios[key[0]], key[1])
}

func sortText(t *requirementText) {
	sort.Strings(t.body)
	for scenario := range t.scenarios {
		sort.Strings(t.scenarios[scenario])
	}
}

// missingScenarios reports a scenario the last batch's restatements all listed that the canonical spec does not have.
func missingScenarios(requirement string, winner winningRestatement, have map[string]struct{}) []string {
	var out []string
	for _, scenario := range winner.scenarios {
		if _, ok := have[scenario]; ok {
			continue
		}
		out = append(out, fmt.Sprintf("%s/%s\n    listed by %s, and not in the canonical spec",
			requirement, scenario, winner.by()))
	}
	return out
}

// unretiredScenarios is the same comparison the other way round, which review caught missing. A restatement replaces a
// requirement WHOLE, so a scenario it does NOT list is one it retires, and a canonical scenario no restatement in the last batch
// mentions is a retirement that did not take effect. Archiving a MODIFIED before the ADDED it refines lands exactly here: the
// ADDED body is re-applied last, every scenario the restatement kept is present, and only the ones it dropped give it away.
//
// Checked against the batch's UNION, not the intersection the other direction uses: a scenario any restatement in the batch kept
// could be there because that one won.
func unretiredScenarios(requirement string, winner winningRestatement, have map[string]struct{}) []string {
	var out []string
	for _, scenario := range sortedKeys(have) {
		if _, ok := winner.everListed[scenario]; ok {
			continue
		}
		out = append(out, fmt.Sprintf("%s/%s\n    in the canonical spec, and retired by %s", requirement, scenario, winner.by()))
	}
	return out
}

// missingText reports prose the batch's restatements all carried that the canonical spec does not have, and canonical prose none
// of them carried.
//
// The first is the loss a scenario heading cannot speak for: a restatement can refine a requirement's wording, or one scenario's
// THEN clause, while listing exactly the scenario names the body it replaces already had, and archiving it before the ADDED it
// refines loses that wording with every name still in place.
//
// The second is that comparison the other way round, and it is the one review had to ask for twice. A restatement whose whole
// change is a DELETION carries no line the canonical spec lacks, so the loss direction alone reports nothing when it is archived
// out of order and the deleted clause survives. I left it out on the assumption that canonical text no restatement carried would
// mostly be legacy hand-edits of `openspec/specs/**` and would drown the report. Measured, it is 14 lines across 12 requirements.
//
// Scenario bodies are compared under their scenario NAME, and only for scenarios both sides have. A scenario that went missing is
// reported once by name; counting its bullets too turned one lost scenario into seven findings, 127 lines across the archive.
func missingText(requirement string, winner winningRestatement, canonical requirementText) []string {
	out := textDiff(requirement, "", winner.by(), winner.kept.body, canonical.body, winner.everKept.body)
	// Scenario text under the scenario's NAME, and only for scenarios both sides have. A scenario that went missing is reported
	// once by name; counting its bullets too turned one lost scenario into seven findings.
	for _, scenario := range sortedKeys(winner.kept.scenarios) {
		canonicalLines, both := canonical.scenarios[scenario]
		if !both {
			continue
		}
		out = append(out, textDiff(requirement, scenario, winner.by(),
			winner.kept.scenarios[scenario], canonicalLines, winner.everKept.scenarios[scenario])...)
	}
	return out
}

// textDiff reports one span of prose in both directions: lines every restatement carried that the canonical spec lacks, and
// canonical lines none of them carried.
func textDiff(requirement, scenario, by string, kept, canonical, everKept []string) []string {
	where := requirement
	if scenario != "" {
		where = requirement + "/" + scenario
	}
	var out []string
	for _, line := range kept {
		if !slices.Contains(canonical, line) {
			out = append(out, fmt.Sprintf("%s\n    text listed by %s, and not in the canonical spec:\n      %s", where, by, line))
		}
	}
	for _, line := range canonical {
		if !slices.Contains(everKept, line) {
			out = append(out, fmt.Sprintf("%s\n    in the canonical spec, and retired by %s:\n      %s", where, by, line))
		}
	}
	return out
}

// winningRestatement is what the last archive BATCH said about one requirement: the changes in it that restated the requirement,
// and the scenarios all of them listed.
type winningRestatement struct {
	changes   []string
	scenarios []string
	// everListed is every scenario ANY restatement in the batch named, which is what a canonical scenario is checked against: one
	// that any of them kept could be there because that one won, and only one none of them kept is a retirement that did not land.
	everListed map[string]struct{}
	// kept is the text every restatement in the batch carried, and everKept the text ANY of them did, for the same reason
	// scenarios is an intersection and everListed a union.
	kept     requirementText
	everKept requirementText
}

// by names the changes a finding is attributed to. Every change in the batch, since which of them won is not recoverable.
func (w winningRestatement) by() string { return strings.Join(w.changes, " and ") }

// lastBatchRestatement returns what the last archive batch to restate a requirement agreed on.
//
// Not the last FOLDER, which is what this did until review pointed out that folders in one batch share a date and so sort
// alphabetically: eight of the sixty-seven archived requirements have more than one restatement in their last batch, and seven of
// those eight restate different scenario sets, so picking the alphabetically last one is a guess that is doing real work.
//
// The intersection is what survives the guess. `openspec archive` replaces a requirement WHOLE, so exactly one of a batch's
// restatements wins and the others are discarded by design; a scenario EVERY one of them listed is therefore in the canonical spec
// whichever won, and its absence is a real loss. A scenario only some listed is unrecoverable, and unrecoverable is silence here,
// for the reason the whole command reports rather than gates. That drops the count on today's tree from 34 to 31.
func lastBatchRestatement(entries []archivedRestatement) winningRestatement {
	last := ""
	for _, e := range entries {
		if d := archiveDate(e.change); d > last {
			last = d
		}
	}
	out := winningRestatement{
		everListed: map[string]struct{}{},
		kept:       requirementText{scenarios: map[string][]string{}},
		everKept:   requirementText{scenarios: map[string][]string{}},
	}
	shared := map[string]int{}
	sharedText := map[[2]string]int{}
	batch := 0
	for _, e := range entries {
		if archiveDate(e.change) != last {
			continue
		}
		batch++
		out.changes = append(out.changes, e.change)
		for _, s := range e.scenarios {
			shared[s]++
			out.everListed[s] = struct{}{}
		}
		// Counted per ENTRY, not per occurrence, which review caught: a restatement repeating an identical bullet would push its
		// count past the batch size and drop the line out of the intersection, so losing every copy would go unreported.
		for key := range textKeys(e.text) {
			sharedText[key]++
			appendText(&out.everKept, key)
		}
	}
	for s, n := range shared {
		if n == batch {
			out.scenarios = append(out.scenarios, s)
		}
	}
	for key, n := range sharedText {
		if n == batch {
			appendText(&out.kept, key)
		}
	}
	sortText(&out.kept)
	sortText(&out.everKept)
	sort.Strings(out.changes)
	sort.Strings(out.scenarios)
	return out
}

// archiveDate is the YYYY-MM-DD an archive folder is prefixed with, or the whole name when it carries no date. It identifies the
// BATCH a change was archived in, which is all a folder name can honestly say: openspec stamps one date on every folder in a
// batch, so the order WITHIN one is not recoverable and nothing here tries to recover it.
//
// Prefix rather than a parse, which also handles the malformed double-date folders that predate this
// (`2026-06-09-2026-06-09-x`): their first ten characters are still the date, and a stricter reader would have to special-case
// them for no gain.
func archiveDate(folder string) string {
	const dateLen = len("2006-01-02")
	if len(folder) < dateLen {
		return folder
	}
	return folder[:dateLen]
}

// canonicalScenarios indexes the canonical tree the way the archived deltas are keyed, so the two sides of the comparison derive
// their keys in one place rather than in two that agree until one is edited.
//
// canonicalRequirements below is the third caller and the reason this is worth saying twice: archive-order asks the same question
// of the same tree, and had its own copy of the key expression until review pointed out that the two commands would then classify
// a requirement differently the moment either was edited.
func canonicalScenarios(scenarios []Scenario) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{})
	for _, s := range scenarios {
		key := s.SpecDir + "/" + slugify(s.Requirement)
		if out[key] == nil {
			out[key] = make(map[string]struct{})
		}
		out[key][slugify(s.Title)] = struct{}{}
	}
	return out
}

// requirementLifecycle is when the archive last ADDED a requirement and when it last RETIRED it, as archive dates.
//
// Dates rather than change names, and empty means never: within a batch the order is not recoverable, so an addition and a
// retirement stamped the same day say nothing about each other.
type requirementLifecycle struct {
	added   string
	retired string
}

// retiredLast reports a retirement no later addition undid.
//
// Equal dates count as retired, which looks like the wrong way round for a file that treats every other same-batch question as
// unanswerable, and review is right that it is. Every change in the CURRENT release carries one date, so an addition and a
// retirement of the same requirement archived remove-then-add land on equal dates, leave the requirement canonical, and are
// exactly the out-of-order outcome this exists to catch. Staying silent there would blind it to the release it runs against.
//
// What makes that safe is the procedure rather than the rule: a historical pair reported on this basis appears in the BEFORE
// report too, so it is not a new line and costs the release engineer nothing. No requirement is in that state today.
func (l requirementLifecycle) retiredLast() bool { return l.retired != "" && l.retired >= l.added }

// canonicalRequirements is the requirement keys of the canonical tree, for a caller that needs only the identities.
func canonicalRequirements(scenarios []Scenario) map[string]struct{} {
	byRequirement := canonicalScenarios(scenarios)
	out := make(map[string]struct{}, len(byRequirement))
	for requirement := range byRequirement {
		out[requirement] = struct{}{}
	}
	return out
}

// collectArchivedRestatements walks the archive subtree and returns each requirement's restatements in archive order, plus when
// each requirement was last added and last retired.
func collectArchivedRestatements(changesDir string) (map[string][]archivedRestatement, map[string]requirementLifecycle, error) {
	archiveDir := filepath.Join(changesDir, archiveDirName)
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	restatements := make(map[string][]archivedRestatement)
	lifecycle := make(map[string]requirementLifecycle)
	for _, name := range names {
		one := &deltaSections{
			removedRequirements:  make(map[string]struct{}),
			addedBy:              make(map[string]map[string]struct{}),
			removedBy:            make(map[string]map[string]struct{}),
			modifiedRestatements: make(map[string]map[string]restatement),
		}
		if err := one.collectChange(filepath.Join(archiveDir, name)); err != nil {
			return nil, nil, err
		}
		for requirement, byChange := range one.modifiedRestatements {
			for _, r := range byChange {
				restatements[requirement] = append(restatements[requirement],
					archivedRestatement{change: name, scenarios: sortedKeys(r.scenarios), text: splitRequirementText(r.lines)})
			}
		}
		for requirement := range one.removedRequirements {
			life := lifecycle[requirement]
			life.retired = max(life.retired, archiveDate(name))
			lifecycle[requirement] = life
		}
		for requirement := range one.addedBy {
			life := lifecycle[requirement]
			life.added = max(life.added, archiveDate(name))
			lifecycle[requirement] = life
		}
	}
	return restatements, lifecycle, nil
}

// runArchiveVerify is the post-archive half of the release checklist's step 1.
func runArchiveVerify(args []string) int {
	fs := flag.NewFlagSet("archive-verify", flag.ContinueOnError)
	specsDir := fs.String("specs-dir", defaultSpecsDir, "root of the openspec/specs tree")
	changesDir := fs.String("changes-dir", defaultChangesDir, "openspec/changes tree, whose archive subtree is read")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	setFlags := userSetFlagNames(fs)
	*specsDir = resolvePathFlag(*specsDir, setFlags["specs-dir"])
	*changesDir = resolvePathFlag(*changesDir, setFlags["changes-dir"])
	for _, dir := range []string{*changesDir, *specsDir} {
		if err := requireDir(dir); err != nil {
			fmt.Fprintf(os.Stderr, "spectrace archive-verify: %v\n", err)
			return 2
		}
	}

	scenarios, err := ParseAllSpecs(*specsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-verify: %v\n", err)
		return 2
	}
	canonical := canonicalScenarios(scenarios)

	text, err := ParseAllRequirementText(*specsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-verify: %v\n", err)
		return 2
	}

	archived, lifecycle, err := collectArchivedRestatements(*changesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-verify: %v\n", err)
		return 2
	}

	return printArchiveVerify(os.Stdout, verifyArchive(archived, canonical, lifecycle, text), len(archived))
}

// printArchiveVerify renders the report. FINDINGS never gate: the tree carries pre-existing entries this pass cannot classify,
// and a command that fails from the day it lands is a command someone adds a skip for. The checklist reads it by DIFFERENCE, so a
// line that was not there before this archive is one this archive caused.
//
// A failed WRITE does gate, and the distinction is the point. The whole procedure is a release engineer diffing this output
// against the run from before archiving, so a report truncated by a broken pipe while the status says it succeeded would hide
// exactly the new line the diff exists to surface. That is the same reasoning report.go records for PR #281, and printArchiveOrder
// for its plan. Returns 2 on a write failure, matching the usage/IO code the rest of the tool uses.
func printArchiveVerify(w io.Writer, findings []string, requirements int) int {
	var werr error
	p := func(format string, args ...any) {
		if werr != nil {
			return
		}
		_, werr = fmt.Fprintf(w, format, args...)
	}

	if len(findings) == 0 {
		p("spectrace: %d archived requirement restatement(s) checked, every scenario still canonical\n", requirements)
	} else {
		p("spectrace: %d finding(s) against what the archived deltas say the canonical spec should hold.\n", len(findings))
		p("%s\n%s\n%s\n%s\n",
			"Compare this list with the one from before the archive. A line that is NEW is damage this archive did, which is",
			"what archiving out of order causes: a scenario or a line of normative text that the deltas say should be canonical",
			"and is not, one they retired that is still there, or a requirement whose retirement did not apply. A line that was",
			"already there is older, and this cannot tell an older loss from something retired before this run.")
		for _, l := range findings {
			p("  %s\n", l)
		}
	}

	if werr != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-verify: write output: %v\n", werr)
		return 2
	}
	return 0
}

// requirementsTouched returns every requirement an archived delta restated or retired, in a stable order.
func requirementsTouched(archived map[string][]archivedRestatement, lifecycle map[string]requirementLifecycle) []string {
	seen := make(map[string]struct{}, len(archived)+len(lifecycle))
	for k := range archived {
		seen[k] = struct{}{}
	}
	for k := range lifecycle {
		seen[k] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
