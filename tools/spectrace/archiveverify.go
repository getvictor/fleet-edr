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

// archivedRestatement is one archived change's ADDED or MODIFIED entry for one requirement, with the folder it came from.
type archivedRestatement struct {
	change string
	// added distinguishes an entry that INTRODUCED the requirement from one that restated it, which the two directions of the
	// check need differently. See lastBatchRestatement for why the retirement direction cannot treat them alike.
	added     bool
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

		winner := lastBatchRestatement(entries, life.added)
		// Nothing from the requirement's CURRENT lifetime, so there is no claim to check it against. Review caught what the
		// obvious guard missed: testing `entries` here tests the list before the lifetime filter empties it, and an empty winner
		// then reports every scenario and every line of a correctly re-added requirement as retired.
		if len(winner.changes) == 0 {
			continue
		}
		losses = append(losses, missingScenarios(requirement, winner, have)...)
		losses = append(losses, unretiredScenarios(requirement, winner, have)...)
		losses = append(losses, missingText(requirement, winner, text[requirement])...)
	}
	sort.Strings(losses)
	return losses
}

// textKeys is a restatement's prose as a SET of (scenario, line) pairs, where an empty scenario means the requirement's own body.
// A set rather than a list because the counting below is "how many restatements carried this", not "how many times it appears".
//
// Which drops multiplicity, and review is right that a span repeating one logical line twice would then survive losing one copy:
// every distinct line is still present, and the order check is skipped because the lengths differ. Not fixed, because it is not
// reachable. Zero of the 1464 spans in the canonical tree and the whole archive repeat a logical line, and comparing multisets
// instead would mean count-aware comparison in both directions of textDiff, in code the strict linter has already pushed past its
// complexity limit twice. If a requirement ever does repeat a line verbatim, one lost copy of it goes unreported.
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
	out := textDiff(requirement, "", winner.by(), winner.kept.body, canonical.body, winner.everKept.body, winner.wrote.body)
	// Scenario text under the scenario's NAME, and only for scenarios both sides have. A scenario that went missing is reported
	// once by name; counting its bullets too turned one lost scenario into seven findings.
	// Over the scenario NAMES the batch agreed on, not over the names that survived the text intersection. Review caught the
	// difference: where two restatements list the same scenario and their bodies share no line, `kept.scenarios` has no key for
	// it, and iterating the keys would silently skip the canonical side of a scenario whose failed retirement is unambiguous. A
	// nil `kept` slice for a scenario is a legitimate answer, and the loop below handles it.
	for _, scenario := range winner.scenarios {
		canonicalLines, both := canonical.scenarios[scenario]
		if !both {
			continue
		}
		out = append(out, textDiff(requirement, scenario, winner.by(),
			winner.kept.scenarios[scenario], canonicalLines, winner.everKept.scenarios[scenario], winner.wrote.scenarios[scenario])...)
	}
	return out
}

// textDiff reports one span of prose in both directions: lines every restatement carried that the canonical spec lacks, and
// canonical lines none of them carried. Plus the case neither direction sees, where the lines all match and their ORDER does not.
//
// `kept`, `canonical` and `everKept` are compared as sets and are sorted for that; `ordered` is the same span as the batch's
// restatements actually wrote it, which is what the sequence check needs.
func textDiff(requirement, scenario, by string, kept, canonical, everKept, ordered []string) []string {
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
	if len(out) == 0 && !slices.Equal(ordered, canonical) && len(ordered) == len(canonical) {
		// Same lines, different sequence, which the two loops above cannot see because they ask only whether each line occurs.
		// A restatement whose only change is the ORDER of a scenario's given/when/then steps is a real refinement, and an
		// out-of-order archive restores the old sequence with every line still present. Reported once for the span rather than
		// per line, since naming which line moved is a diff and this is a report.
		//
		// Only when the sets match, so it never fires alongside a missing or surviving line: those name the difference already.
		// No span on today's tree is in this state, and the check costs one comparison.
		out = append(out, fmt.Sprintf("%s\n    ordered differently by %s than in the canonical spec", where, by))
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
	// wrote is the span in the order the batch's restatements wrote it, which the sorted sets above cannot answer. Taken from one
	// restatement rather than merged: where a batch's restatements disagree on order, which of them won is exactly what is not
	// recoverable, so the sequence check is only meaningful for a batch that agrees, and a batch that agrees has one order.
	wrote requirementText
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
func lastBatchRestatement(entries []archivedRestatement, addedOn string) winningRestatement {
	entries = currentLifetime(entries, addedOn)
	out := winningRestatement{
		everListed: map[string]struct{}{},
		kept:       requirementText{scenarios: map[string][]string{}},
		everKept:   requirementText{scenarios: map[string][]string{}},
	}
	if len(entries) == 0 {
		return out
	}
	last := ""
	for _, e := range entries {
		if d := archiveDate(e.change); d > last {
			last = d
		}
	}

	// everListed and everKept are the EXCUSE set: the canonical-side checks read them as "some delta in this batch kept this, so
	// its presence in the tree is not an unapplied retirement". Widening that set weakens those checks, which is the opposite of
	// what widening the CLAIM set does, and is why the two directions cannot read the same entries.
	//
	// So the excuse set is built from the batch's MODIFIED entries whenever it has any. A MODIFIED replaces the requirement whole
	// and is sequenced after the ADDED it refines (see archive-order), so what the MODIFIED omits is retired even if the ADDED
	// listed it. Review caught this as a regression the fold introduced: for a same-date ADDED listing {shared, retired} beside a
	// MODIFIED listing {shared}, letting the ADDED excuse `retired` silenced a finding the MODIFIED-only input used to report,
	// which is exactly the out-of-order damage this command exists to catch.
	//
	// A batch of ADDED entries alone is its own authority, which is the case issue #909 added and where there is nothing else to
	// read. The LOSS direction is unaffected and still intersects every entry: claiming less can only miss a finding, never invent
	// one.
	excuseFrom := func(e archivedRestatement) bool { return !e.added }
	if !slices.ContainsFunc(entries, func(e archivedRestatement) bool {
		return archiveDate(e.change) == last && !e.added
	}) {
		excuseFrom = func(archivedRestatement) bool { return true }
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
			if excuseFrom(e) {
				out.everListed[s] = struct{}{}
			}
		}
		// Counted per ENTRY, not per occurrence, which review caught: a restatement repeating an identical bullet would push its
		// count past the batch size and drop the line out of the intersection, so losing every copy would go unreported.
		for key := range textKeys(e.text) {
			sharedText[key]++
			if excuseFrom(e) {
				appendText(&out.everKept, key)
			}
		}
		// The written ORDER is recorded only for a batch of ONE, which is the batch the sequence check can speak for. Where two
		// restatements are in the batch, which of them the archive applied is exactly what is not recoverable, so neither of
		// their orders is "the" order: taking one anyway reported six spans as reordered on the real tree, every one of them a
		// multi-change batch.
		out.wrote = e.text
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
	if batch > 1 {
		out.wrote = requirementText{}
	}
	sortText(&out.kept)
	sortText(&out.everKept)
	sort.Strings(out.changes)
	sort.Strings(out.scenarios)
	return out
}

// currentLifetime drops restatements archived before the requirement was last ADDED.
//
// Those describe a PREVIOUS lifetime of it, which review caught: a requirement retired and later re-added has a new body, and
// comparing the old one against it reports a correct re-add as damage. Same-date ones are kept, so the batch that did the
// re-adding is still checked.
func currentLifetime(entries []archivedRestatement, addedOn string) []archivedRestatement {
	if addedOn == "" {
		return entries
	}
	var out []archivedRestatement
	for _, e := range entries {
		if archiveDate(e.change) >= addedOn {
			out = append(out, e)
		}
	}
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
			addedStatements:      make(map[string]map[string]restatement),
		}
		if err := one.collectChange(filepath.Join(archiveDir, name)); err != nil {
			return nil, nil, err
		}
		// Both sections, because an ADDED entry is as much a claim about what the canonical tree should hold after archiving as a
		// MODIFIED one. Until issue #909 only MODIFIED was collected, so a requirement that was ADDED and never restated had NO
		// claim against it at all: the archive could drop one of its scenarios, or the last line of its last requirement, and
		// nothing here would say so. That is not a rare shape. Most requirements are introduced once and never restated.
		//
		// They are folded into one list rather than compared separately, so the existing winner selection applies unchanged: the
		// latest batch wins, and within a batch the claims are INTERSECTED. An ADDED and a MODIFIED of one requirement in one
		// batch therefore claim only what both list, which under-claims when the MODIFIED refined the requirement and can only
		// miss a finding, never invent one. The batch's internal order stays unrecoverable and nothing here pretends otherwise.
		//
		// The entry's SECTION is kept, because the excuse set the canonical-side checks read cannot be widened the same way. See
		// lastBatchRestatement: an earlier version of this fold read both directions from all entries and silenced a real
		// finding.
		for _, section := range []struct {
			entries map[string]map[string]restatement
			added   bool
		}{{one.modifiedRestatements, false}, {one.addedStatements, true}} {
			for requirement, byChange := range section.entries {
				for _, r := range byChange {
					restatements[requirement] = append(restatements[requirement], archivedRestatement{
						change: name, added: section.added,
						scenarios: sortedKeys(r.scenarios), text: splitRequirementText(r.lines),
					})
				}
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

	exceptions, err := loadArchiveExceptions(exceptionsPathFor(*specsDir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-verify: %v\n", err)
		return 2
	}
	findings := verifyArchive(archived, canonical, lifecycle, text)
	outstanding, excused, matched := applyExceptions(findings, exceptions)
	problems := validateExceptions(exceptions, canonicalRequirements(scenarios), matched)

	return printArchiveVerify(os.Stdout, outstanding, excused, problems, len(archived))
}

// printArchiveVerify renders the report. FINDINGS never gate: the tree carries pre-existing entries this pass cannot classify,
// and a command that fails from the day it lands is a command someone adds a skip for. The checklist reads it by DIFFERENCE, so a
// line that was not there before this archive is one this archive caused.
//
// A failed WRITE does gate, and the distinction is the point. The whole procedure is a release engineer diffing this output
// against the run from before archiving, so a report truncated by a broken pipe while the status says it succeeded would hide
// exactly the new line the diff exists to surface. That is the same reasoning report.go records for PR #281, and printArchiveOrder
// for its plan. Returns 2 on a write failure, matching the usage/IO code the rest of the tool uses.
func printArchiveVerify(w io.Writer, findings []string, excused []excusedFinding, problems []string, requirements int) int {
	var werr error
	p := func(format string, args ...any) {
		if werr != nil {
			return
		}
		_, werr = fmt.Fprintf(w, format, args...)
	}

	switch {
	case len(findings) == 0 && len(excused) > 0:
		// The end state this audit is driving toward, and it is NOT the same as a clean tree: every discrepancy is accounted
		// for, but the excused section below still lists real differences from what the archive claimed. Saying "every scenario
		// still canonical" here would contradict the lines printed immediately after it.
		p("spectrace: %d archived requirement restatement(s) checked, no outstanding findings; every discrepancy is excused below\n",
			requirements)
	case len(findings) == 0:
		p("spectrace: %d archived requirement restatement(s) checked, every scenario still canonical\n", requirements)
	default:
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

	printExcused(p, excused)

	// A malformed or stale exception DOES gate, where a finding does not. The findings list is a report a human diffs; the
	// exceptions file is a set of claims this tool is the only checker of. An entry naming a survivor that no longer exists, or
	// one left behind after the finding it excused was repaired, silently shrinks what the report covers, and nothing else in
	// the pipeline would catch it.
	if len(problems) > 0 {
		p("\nspectrace: %d problem(s) in %s. Each entry must name a covered_by that resolves, or a tracked_by issue, "+
			"carry a reason, and excuse at least one finding.\n", len(problems), defaultExceptionsFile)
		for _, l := range problems {
			p("  %s\n", l)
		}
	}

	if werr != nil {
		fmt.Fprintf(os.Stderr, "spectrace archive-verify: write output: %v\n", werr)
		return 2
	}
	if len(problems) > 0 {
		return 1
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
