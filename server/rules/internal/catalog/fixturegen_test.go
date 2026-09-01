//go:build fixturegen

// Package-local generator for the imported corpus's smoke fixtures (issue #773).
//
// Run it, do not schedule it:
//
//	go test -tags fixturegen -run TestGenerateImportedSmokeFixtures ./server/rules/internal/catalog/
//
// Behind a build tag because a generator that runs in CI is not a regression gate, it is a way to hide one. If a fixture stops
// firing, the honest outcome is a red build; regenerating on every run would rewrite the fixture to match whatever the rule now
// does and report success. The output is committed and is thereafter an ordinary hand-maintainable fixture: to fix a genuine
// behaviour change you edit the file and say why, you do not re-run this.
//
// It lives in the catalog package rather than under tools/ because the corpus is embedded in an internal package and Go's
// visibility rule puts it out of reach from anywhere else in the tree.
//
// What it does NOT do is decide whether a fixture is correct. It synthesises a candidate event from the literals a rule asks for
// and writes it out; TestCatalogFixturesStillFire is what then proves the rule actually fires on it. A rule this cannot satisfy is
// reported by name at the end and gets a hand-written fixture instead, which is the right division: the generator handles the
// mechanical majority and a human handles the ones that need thought.
package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
)

// generatedFixtureName is the single file each imported rule gets. One positive per rule is the bar issue #773 sets for the
// vendored corpus ("at least a smoke fixture"); the authored rules carry hand-written negatives as well, because there a human
// decided what the meaningful near miss is, and a generated near miss would only ever be "the same event with one field spoiled".
const generatedFixtureName = "positive_smoke.json"

func TestGenerateImportedSmokeFixtures(t *testing.T) {
	t.Parallel()

	corpus, err := sigmaFilesUnder(importedCorpus, "imported")
	require.NoError(t, err)

	byID := map[string]api.Rule{}
	for _, r := range MustLoadImported() {
		byID[r.ID()] = r
	}

	var wrote, skipped int
	var declined []string
	for _, path := range corpus {
		id := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		rule, inCatalog := byID[id]
		if !inCatalog {
			continue // refused at import; it is not in the catalog, so it needs no fixture.
		}
		dir := filepath.Join("fixtures", id)
		if _, statErr := os.Stat(dir); statErr == nil {
			skipped++
			continue // already has fixtures, generated or hand-written; never overwrite.
		}

		raw, readErr := importedCorpus.ReadFile(path)
		require.NoError(t, readErr)
		events, buildErr := candidateEvents(id, raw)
		if buildErr != nil {
			declined = append(declined, fmt.Sprintf("%s: %v", id, buildErr))
			continue
		}

		require.NoError(t, os.MkdirAll(dir, 0o750))
		require.NoError(t, writeFixture(filepath.Join(dir, generatedFixtureName), events, id, rule.Doc().Severity))
		wrote++
	}

	sort.Strings(declined)
	t.Logf("wrote %d, skipped %d that already had fixtures, declined %d", wrote, skipped, len(declined))
	for _, d := range declined {
		t.Logf("  DECLINED %s", d)
	}
}

// candidateEvents synthesises the fork+exec pair (plus the parent's, when the rule reads ParentImage) that trips a rule.
//
// The rule's own compiled detection is the ORACLE. Candidates are enumerated mechanically and each is offered to
// sigma.Rule.Matches; the first the real matcher accepts is the one written out. An earlier version parsed the condition here to
// work out which selections had to hold together, which was a second, weaker implementation of a grammar the sigma package
// already owns: it split on literal " and "/" or " and so lost nested precedence, `(a or b) and c` dropping the {a,c} candidate.
// Asking the matcher removes the shadow grammar and makes the answer exact rather than approximate.
func candidateEvents(ruleID string, raw []byte) ([]detectionapi.Event, error) {
	var f sigmaFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	var block map[string]any
	if err := f.Detection.Decode(&block); err != nil {
		return nil, fmt.Errorf("decode detection: %w", err)
	}
	compiled, err := sigma.Compile(block)
	if err != nil {
		return nil, fmt.Errorf("compile detection: %w", err)
	}

	var names []string
	for name := range block {
		// A filter's literals are what the event must NOT carry, so building from one produces the very event the rule exists to
		// stay quiet on. The matcher would reject it anyway; skipping is just not wasting a candidate on it.
		if name != "condition" && !strings.HasPrefix(name, "filter") {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var best *subject
	for _, group := range candidateGroups(names) {
		for _, cand := range subjectsFor(block, group) {
			if !compiled.Matches(cand) {
				continue
			}
			// A candidate naming a real subject binary beats one that leaves the rule's unconstrained Image blank, so keep
			// looking briefly rather than taking the first match outright.
			if best == nil || (best.image == "" && cand.image != "") {
				c := cand
				best = &c
			}
			if best.image != "" {
				break
			}
		}
		if best != nil && best.image != "" {
			break
		}
	}
	if best == nil {
		return nil, errors.New("no combination of this rule's selections produced an event its own matcher accepts")
	}

	image := best.image
	if image == "" {
		// The rule constrains only the command line or the parent, so any plausible subject satisfies it. Named rather than left
		// empty: a record with no path reads as broken rather than as an event.
		image = "/usr/bin/fixture-subject"
	}

	const childPID, parentPID = 4900, 4800
	argv := append([]string{filepath.Base(image)}, best.args...)
	var events []detectionapi.Event
	ppid := 1
	if best.parent != "" {
		ppid = parentPID
		events = append(events,
			forkEvent(ruleID+"-parent-fork", parentPID, 1, 1_000_000_000),
			execEvent(ruleID+"-parent-exec", parentPID, 1, best.parent, []string{filepath.Base(best.parent)}, 1_010_000_000))
	}
	return append(events,
		forkEvent(ruleID+"-fork", childPID, ppid, 1_020_000_000),
		execEvent(ruleID+"-exec", childPID, ppid, image, argv, 1_030_000_000)), nil
}

// subject is a candidate event expressed as the Sigma fields the taxonomy supplies for an exec, so the compiled rule can be asked
// about it directly.
type subject struct {
	image, parent string
	args          []string
}

// Field makes a candidate a sigma.Event. The three fields are the ones the imported corpus reads; anything else is reported
// absent, which is what an exec event genuinely carrying none of it would report.
func (s subject) Field(name string) ([]string, bool) {
	switch name {
	case "Image":
		return []string{s.image}, s.image != ""
	case "ParentImage":
		return []string{s.parent}, s.parent != ""
	case "CommandLine":
		// ALWAYS present, even with no argv beyond the binary: a real exec event always carries a command line, and reporting it
		// absent made susp_browser_child_process's `filter_optional_empty: CommandLine: ''` match, so the rule's own
		// `not 1 of filter_optional_*` rejected every candidate. The generator has to model the event faithfully, not minimally.
		return []string{strings.Join(append([]string{filepath.Base(s.image)}, s.args...), " ")}, true
	}
	return nil, false
}

// candidateGroups enumerates the selection sets worth trying, smallest first, WITHOUT interpreting the condition.
//
// Every non-empty subset, because anything less can miss the answer: singletons plus pairs plus the whole set left
// create_hidden_account uncovered, whose condition needs three of its four selections and specifically NOT the fourth, which
// matches on a regex. Smallest first so the simplest event that satisfies a rule is the one written out.
//
// Exhaustive is affordable here (the widest rule in the corpus has five selections) and it is what lets the matcher be the only
// thing deciding correctness: this only has to be generous enough to contain a right answer, never to know which one it is. A
// pathologically wide rule falls back to the cheap enumeration rather than to 2^n.
func candidateGroups(names []string) [][]string {
	const exhaustiveLimit = 10
	if len(names) > exhaustiveLimit {
		groups := make([][]string, 0, len(names)+1)
		for _, n := range names {
			groups = append(groups, []string{n})
		}
		return append(groups, names)
	}

	bySize := make([][][]string, len(names)+1)
	for mask := 1; mask < 1<<len(names); mask++ {
		var group []string
		for i, n := range names {
			if mask&(1<<i) != 0 {
				group = append(group, n)
			}
		}
		bySize[len(group)] = append(bySize[len(group)], group)
	}
	var groups [][]string
	for _, sized := range bySize {
		groups = append(groups, sized...)
	}
	return groups
}

// subjectsFor expands one selection set into the candidates it can produce.
//
// A Sigma search whose value is a LIST OF MAPS is a set of alternative maps, not one merged map, so each is expanded separately:
// merging them put both branches of a rule into one fixture, and either branch could then keep it green while the other
// regressed. Within a map, a list value is an OR, so the first entry is taken unless the modifier is `|all`.
func subjectsFor(block map[string]any, group []string) []subject {
	combos := []subject{{}}
	for _, name := range group {
		var alternatives []map[string]any
		switch v := block[name].(type) {
		case map[string]any:
			alternatives = []map[string]any{v}
		case []any:
			for _, item := range v {
				if m, ok := item.(map[string]any); ok {
					alternatives = append(alternatives, m)
				}
			}
		}
		var next []subject
		for _, base := range combos {
			for _, alt := range alternatives {
				if merged, ok := applyMap(base, alt); ok {
					next = append(next, merged)
				}
			}
		}
		if len(next) == 0 {
			return nil
		}
		combos = next
	}
	return combos
}

// applyMap folds one selection map into a candidate, reporting false when it asks for something no literal value can supply.
func applyMap(base subject, m map[string]any) (subject, bool) {
	out := subject{image: base.image, parent: base.parent, args: append([]string{}, base.args...)}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic output, so regenerating an unchanged corpus is a no-op diff.
	for _, k := range keys {
		field, modifier, _ := strings.Cut(k, "|")
		// A regex is a PATTERN, not a value: writing `(.){200,}` into argv would satisfy the condition only by coincidence.
		if strings.Contains(modifier, "re") {
			return subject{}, false
		}
		values := valuesOf(m[k])
		if !strings.Contains(modifier, "all") && len(values) > 1 {
			values = values[:1]
		}
		for _, val := range values {
			switch field {
			case "Image":
				if out.image == "" {
					out.image = realisticPath(val, modifier)
				}
			case "ParentImage":
				if out.parent == "" {
					out.parent = realisticPath(val, modifier)
				}
			case "CommandLine":
				out.args = append(out.args, val)
			default:
				return subject{}, false
			}
		}
	}
	return out, true
}

// valuesOf normalises one Sigma right-hand side to the strings it offers.
func valuesOf(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case int:
		return []string{strconv.Itoa(t)}
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// realisticPath turns a bare leaf into somewhere a binary actually lives.
//
// `Image|endswith: '/osascript'` is satisfied by the literal itself, but `/osascript` is not a path any macOS host would report,
// and these fixtures are read as examples of the telemetry a rule is about. Only extended for endswith/contains, where adding to
// the left-hand side cannot break the match; an exact match is left exactly as written. The matcher verifies the result either
// way, so a wrong guess here is caught rather than shipped.
func realisticPath(value, modifier string) string {
	switch {
	case !strings.HasPrefix(value, "/"):
		return "/usr/bin/" + value
	case strings.Count(value, "/") == 1 && (strings.Contains(modifier, "endswith") || strings.Contains(modifier, "contains")):
		return "/usr/bin" + value
	default:
		return value
	}
}

func forkEvent(id string, pid, ppid int, ts int64) detectionapi.Event {
	return detectionapi.Event{
		EventID: id, HostID: "fixture-host", TimestampNs: ts, EventType: "fork",
		Payload: json.RawMessage(fmt.Sprintf(`{"child_pid": %d, "parent_pid": %d}`, pid, ppid)),
	}
}

func execEvent(id string, pid, ppid int, path string, argv []string, ts int64) detectionapi.Event {
	args, err := json.Marshal(argv)
	if err != nil {
		panic(err) // argv is a []string this file just built; marshalling one cannot fail.
	}
	return detectionapi.Event{
		EventID: id, HostID: "fixture-host", TimestampNs: ts, EventType: "exec",
		Payload: json.RawMessage(fmt.Sprintf(
			`{"pid": %d, "ppid": %d, "path": %q, "args": %s, "uid": 501, "gid": 20}`, pid, ppid, path, args)),
	}
}

// writeFixture emits the compact one-event-per-record shape the hand-written fixtures already use.
//
// Not json.MarshalIndent: that spreads every payload field onto its own line, which turned a two-event fixture into seventy and
// the corpus into three thousand lines of diff nobody can read. A fixture is meant to be skimmed as "these events, that finding",
// and the whole point is lost if the reader has to scroll one.
func writeFixture(path string, events []detectionapi.Event, ruleID, severity string) error {
	var b strings.Builder
	b.WriteString("{\n  \"events\": [\n")
	for i, e := range events {
		payload, err := compactJSON(e.Payload)
		if err != nil {
			return fmt.Errorf("%s: compact payload: %w", path, err)
		}
		fmt.Fprintf(&b,
			"    {\"event_id\": %q, \"host_id\": %q, \"timestamp_ns\": %d, \"event_type\": %q,\n     \"payload\": %s}",
			e.EventID, e.HostID, e.TimestampNs, e.EventType, payload)
		if i < len(events)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	// Severity is pinned because Replay equality-matches it: a fixture that omits it asserts the empty string and fails for a
	// reason unrelated to whether the rule fired. It also makes a silent severity downgrade a test failure.
	b.WriteString("  ],\n  \"expected_findings\": [\n")
	fmt.Fprintf(&b, "    {\"rule_id\": %q, \"severity\": %q}\n", ruleID, severity)
	b.WriteString("  ]\n}\n")
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func compactJSON(raw json.RawMessage) (string, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return "", err
	}
	return buf.String(), nil
}
