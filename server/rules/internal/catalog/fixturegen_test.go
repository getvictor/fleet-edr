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

// candidateEvents synthesises the fork+exec pair (plus the parent's, when the rule reads ParentImage) that should trip a rule.
func candidateEvents(ruleID string, raw []byte) ([]detectionapi.Event, error) {
	var f sigmaFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	var block map[string]any
	if err := f.Detection.Decode(&block); err != nil {
		return nil, fmt.Errorf("decode detection: %w", err)
	}

	// The condition decides which selections have to hold TOGETHER. Merging everything is right for `all of x_*` and wrong for
	// `1 of x_*`, where the selections are alternatives: the file-and-directory-discovery rule offers five, each with its own
	// Image, so merging paired /usr/bin/file with a flag belonging to /bin/ls and matched nothing. Conditions like
	// `selection1 and 1 of selection_cli*` need both halves: the mandatory one plus ONE of the alternatives.
	condition, _ := block["condition"].(string)
	// Every branch that builds is collected, then the one naming a subject binary wins. Taking the first that merely succeeds
	// picked the command-line-only branch of `1 of selection*` rules and produced an event with no Image at all: still a match,
	// because such a rule does not constrain the image, but useless as an illustration of what the rule is for.
	var image, parent string
	var args []string
	var lastErr error
	built := false
	for _, group := range candidateGroups(condition, block) {
		gotImage, gotParent, gotArgs, err := buildFrom(block, group)
		if err != nil {
			lastErr = err
			continue
		}
		if !built || (image == "" && gotImage != "") {
			image, parent, args, built = gotImage, gotParent, gotArgs, true
		}
		if image != "" {
			break
		}
	}
	if !built {
		if lastErr == nil {
			lastErr = errors.New("condition names no selection this generator can build from")
		}
		return nil, lastErr
	}
	if image == "" {
		// The rule constrains only the command line or the parent, so any plausible subject satisfies it. Named rather than left
		// empty: a fixture with no path at all reads as a broken record instead of as an event.
		image = "/usr/bin/fixture-subject"
	}

	const childPID, parentPID = 4900, 4800
	argv := append([]string{filepath.Base(image)}, args...)
	events := []detectionapi.Event{}
	ppid := 1
	if parent != "" {
		ppid = parentPID
		events = append(events,
			forkEvent(ruleID+"-parent-fork", parentPID, 1, 1_000_000_000),
			execEvent(ruleID+"-parent-exec", parentPID, 1, parent, []string{filepath.Base(parent)}, 1_010_000_000))
	}
	return append(events,
		forkEvent(ruleID+"-fork", childPID, ppid, 1_020_000_000),
		execEvent(ruleID+"-exec", childPID, ppid, image, argv, 1_030_000_000)), nil
}

// candidateGroups turns a Sigma condition into the sets of selections that would each satisfy it, best first.
//
// Only the shapes the vendored corpus actually uses are handled, and an unrecognised one falls back to "every non-filter
// selection", which either builds something the verification step accepts or is declined by name. Guessing more cleverly than the
// corpus requires would be inventing semantics; the replay gate is what decides whether a guess was right.
//
//   - `a or b`      two independent branches, tried in order
//   - `a and b`     both, merged
//   - `all of p_*`  every selection whose name starts with p_
//   - `1 of p_*`    each matching selection on its own, as alternatives
//   - `not ...`     dropped: filters are already excluded by name, and a negated clause names what must NOT hold
func candidateGroups(condition string, block map[string]any) [][]string {
	selectable := func(name string) bool {
		_, ok := block[name]
		return ok && name != "condition" && !strings.HasPrefix(name, "filter")
	}
	matching := func(pattern string) []string {
		prefix := strings.TrimSuffix(pattern, "*")
		var out []string
		for name := range block {
			if selectable(name) && strings.HasPrefix(name, prefix) {
				out = append(out, name)
			}
		}
		sort.Strings(out)
		return out
	}

	var groups [][]string
	for branch := range strings.SplitSeq(condition, " or ") {
		// Each term contributes either one fixed set of names or several alternatives; the branch's candidates are the product.
		combos := [][]string{{}}
		usable := true
		for term := range strings.SplitSeq(branch, " and ") {
			// Parentheses group terms rather than naming one; the corpus uses them in exactly one rule, and leaving them attached
			// made `(ishidden_option_declaration` match no selection at all.
			term = strings.Trim(strings.TrimSpace(term), "()")
			if term == "" || strings.HasPrefix(term, "not ") {
				continue
			}
			var alternatives [][]string
			switch {
			case strings.HasPrefix(term, "all of "):
				alternatives = [][]string{matching(strings.TrimPrefix(term, "all of "))}
			case strings.HasPrefix(term, "1 of "):
				for _, n := range matching(strings.TrimPrefix(term, "1 of ")) {
					alternatives = append(alternatives, []string{n})
				}
			case selectable(term):
				alternatives = [][]string{{term}}
			}
			if len(alternatives) == 0 {
				// A term this cannot read must INVALIDATE the branch, not be skipped. Skipping built a group holding only the
				// terms that parsed, which produced an event satisfying no branch of the condition and a fixture that fired
				// nothing: silently degrading where declining and asking for a hand-written fixture is the honest outcome.
				usable = false
				break
			}
			var next [][]string
			for _, base := range combos {
				for _, alt := range alternatives {
					next = append(next, append(append([]string{}, base...), alt...))
				}
			}
			combos = next
		}
		if !usable {
			continue
		}
		for _, c := range combos {
			if len(c) > 0 {
				groups = append(groups, c)
			}
		}
	}
	if len(groups) == 0 {
		var all []string
		for name := range block {
			if selectable(name) {
				all = append(all, name)
			}
		}
		sort.Strings(all)
		groups = [][]string{all}
	}
	return groups
}

// buildFrom assembles the subject, parent and argv one group of selections requires, or explains why it cannot.
func buildFrom(block map[string]any, names []string) (image, parent string, args []string, err error) {
	for _, name := range names {
		for _, lit := range literalsOf(block[name]) {
			// A regex is a PATTERN, not a value: writing `(.){200,}` into argv satisfies the condition only by coincidence, so a
			// selection that needs one is declined and the caller tries another.
			if strings.Contains(lit.modifier, "re") {
				return "", "", nil, fmt.Errorf("selection %q matches on a regex, which no literal value satisfies", name)
			}
			switch lit.field {
			case "Image":
				if image == "" {
					image = realisticPath(lit.value, lit.modifier)
				}
			case "ParentImage":
				if parent == "" {
					parent = realisticPath(lit.value, lit.modifier)
				}
			case "CommandLine":
				args = append(args, lit.value)
			default:
				return "", "", nil, fmt.Errorf("field %q is not one this generator can supply", lit.field)
			}
		}
	}
	if image == "" && parent == "" && len(args) == 0 {
		return "", "", nil, errors.New("no literals to build an event from")
	}
	return image, parent, args, nil
}

// literal is one value a selection asks a field to carry.
type literal struct{ field, modifier, value string }

// literalsOf flattens one selection into the values it requires.
//
// A Sigma list is an OR, so only the FIRST value of a group is taken: cramming every alternative into one command line produces
// something that matches but that no machine ever ran (`touch -t -acmr -d -r`), and a smoke fixture doubles as a sample of what
// the rule is for. `|all` is the exception the format defines, where every value genuinely has to be present.
func literalsOf(sel any) []literal {
	var out []literal
	switch v := sel.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic output, so regenerating an unchanged corpus is a no-op diff.
		for _, k := range keys {
			field, modifier, _ := strings.Cut(k, "|")
			for i, val := range valuesOf(v[k]) {
				if i > 0 && !strings.Contains(modifier, "all") {
					break
				}
				out = append(out, literal{field: field, modifier: modifier, value: val})
			}
		}
	case []any:
		for _, item := range v {
			out = append(out, literalsOf(item)...)
		}
	}
	return out
}

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
// and these fixtures are read as examples of the telemetry a rule is about. Only safe for endswith/contains, where extending the
// left-hand side cannot break the match; an exact match is left exactly as written.
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
