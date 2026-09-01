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
// Two independent things check the output, and they check different halves.
//
// The generator itself never writes a candidate the rule's OWN compiled detection rejects: it synthesises events from the
// literals a rule asks for and offers each to sigma.Rule.Matches, so what lands on disk already satisfies the Sigma condition.
// What that cannot tell you is whether the event survives the real pipeline, since the matcher sees a field lookup rather than a
// decoded payload with a materialised process behind it. TestCatalogFixturesStillFire is what proves that half, and it has
// rejected candidates this accepted more than once.
//
// A rule no combination satisfies is reported by name at the end and gets a hand-written fixture instead. That is the right
// division: the generator handles the mechanical majority, a human handles the ones that need thought.
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

// Deliberately NOT parallel, and the paralleltest exemption is the point rather than an oversight: this writes under fixtures/,
// which the package's coverage and replay tests read. Those two DO run in parallel, so they resume only after the sequential
// pass finishes; staying sequential here is what guarantees the tree is complete before anything reads it. Marking this parallel
// too would let a run of `go test -tags fixturegen ./...` without the documented -run filter race directory creation against
// TestCatalogFixturesStillFire and report whatever it happened to see.
//
//nolint:paralleltest // mutates the fixtures/ tree that the package's other tests read; see above.
func TestGenerateImportedSmokeFixtures(t *testing.T) {
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
		for _, cand := range withSubjectFallback(subjectsFor(block, group)) {
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

	const childPID, parentPID = 4900, 4800
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
		execEvent(ruleID+"-exec", childPID, ppid, image, best.argv(), 1_030_000_000)), nil
}

// subject is a candidate event expressed as the Sigma fields the taxonomy supplies for an exec, so the compiled rule can be asked
// about it directly.
type subject struct {
	image, parent string
	args          []string
	// needsTrailer records that some value ended in a space, so the rule is asking for a token after it. The joined argv has no
	// trailing separator, so without something following, a value like 'hidden ' cannot match however the fixture is written.
	needsTrailer bool
}

// argv renders the candidate's command line the way the agent would: argv[0] then the arguments.
//
// argv[0] is the FULL image path when one of the rule's own command-line literals opened with that path, because then the literal
// was describing the executable and not an argument; the leading token is dropped so the path is not repeated. Otherwise it is
// the basename, which is what an ordinary invocation carries.
const trailingOperand = "/tmp/fixture-target"

func (s subject) argv() []string {
	args := s.args
	if s.needsTrailer {
		args = append(append([]string{}, args...), trailingOperand)
	}
	if len(args) > 0 && strings.HasPrefix(args[0], "/") && strings.HasSuffix(s.image, args[0]) {
		return append([]string{s.image}, args[1:]...)
	}
	return append([]string{filepath.Base(s.image)}, args...)
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
		// Always present for a GENERATED event, which always has an argv[0]. Not a claim about real ones: sigmabind reports an
		// exec with no arguments as carrying no CommandLine at all, deliberately, so that a rule written `CommandLine: null`
		// matches it. Reporting it absent here made susp_browser_child_process's `filter_optional_empty: CommandLine: ''` match
		// and its own `not 1 of filter_optional_*` then rejected every candidate.
		return []string{strings.Join(s.argv(), " ")}, true
	}
	return nil, false
}

// fixtureSubject is the stand-in binary for a rule that constrains only the command line or the parent. Named rather than left
// empty, because a record with no path reads as a broken row rather than as an event.
const fixtureSubject = "/usr/bin/fixture-subject"

// withSubjectFallback adds, for any candidate with no Image, the same candidate WITH the stand-in subject.
//
// Offered as an extra candidate rather than patched onto the winner afterwards. Filling Image also fills argv[0] and so changes
// the joined command line, so a candidate approved without one is not the candidate that would be written: an `Image: null`
// clause or an image-bearing filter can reject the filled-in version. Patching after the oracle had spoken produced exactly that
// bug twice in this file's history, once here and once with the trailing operand, and each time a re-check was bolted on to
// compensate. Enumerating the variant instead makes verification the LAST step, so the subject written out is by construction the
// subject the matcher accepted and no re-check is needed.
func withSubjectFallback(cands []subject) []subject {
	out := make([]subject, 0, len(cands)*2)
	for _, c := range cands {
		out = append(out, c)
		if c.image == "" {
			withSubject := c
			withSubject.image = fixtureSubject
			out = append(out, withSubject)
		}
	}
	return out
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
	out := subject{image: base.image, parent: base.parent, args: append([]string{}, base.args...), needsTrailer: base.needsTrailer}
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
					out.image = plausiblePath(val, modifier)
				}
			case "ParentImage":
				if out.parent == "" {
					out.parent = plausiblePath(val, modifier)
				}
			case "CommandLine":
				// A corpus value is a fragment of a COMMAND LINE, not one argv entry. Emitting it whole produced
				// `TeamViewer_Desktop /TeamViewer_Desktop --IPCport ...` and `args:["chflags","hidden "]`, both of which satisfy
				// their predicate only because the pattern text was copied verbatim into the event. Real argv elements carry no
				// surrounding spaces: sigmabind's commandLine joins them, and the join is what supplies the boundaries a value
				// like ' -d ' or 'hidden ' is written to require.
				//
				// So the value is split into bare tokens, and a trailing space is remembered rather than embedded: it means the
				// rule needs something to FOLLOW this fragment, which trailingOperand supplies below.
				out.args = append(out.args, strings.Fields(val)...)
				if strings.HasSuffix(val, " ") {
					out.needsTrailer = true
				}
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

// knownLocations pins the binaries this corpus names that do NOT live in /usr/bin.
//
// Guessing /usr/bin for everything put nineteen binaries in the wrong directory: the shells and core tools are in /bin, the
// diagnostics in /usr/sbin, shutdown in /sbin, PlistBuddy in /usr/libexec. That matters because a fixture is read as a sample of
// real telemetry and because agent/hostid already pins /usr/sbin/ioreg, and the MATCHER CANNOT CATCH IT: these rules are written
// `Image|endswith`, so /usr/bin/launchctl satisfies them exactly as well as the canonical /bin/launchctl. Location fidelity is
// the one property the oracle does not check, which is why it is pinned by hand here.
//
// Every entry was resolved against a real macOS host rather than recalled. Anything absent falls through to the /usr/bin default,
// which is right for the corpus's third-party binaries (jamf, TeamViewer) that live wherever their vendor installed them.
//
//nolint:gosec // G101 fires on the "firmwarepasswd" entry: every value here is a binary path, not a credential.
var knownLocations = map[string]string{
	"PlistBuddy":      "/usr/libexec/PlistBuddy",
	"arp":             "/usr/sbin/arp",
	"bash":            "/bin/bash",
	"dd":              "/bin/dd",
	"dseditgroup":     "/usr/sbin/dseditgroup",
	"dsenableroot":    "/usr/sbin/dsenableroot",
	"firmwarepasswd":  "/usr/sbin/firmwarepasswd",
	"installer":       "/usr/sbin/installer",
	"ioreg":           "/usr/sbin/ioreg",
	"launchctl":       "/bin/launchctl",
	"netstat":         "/usr/sbin/netstat",
	"rm":              "/bin/rm",
	"screencapture":   "/usr/sbin/screencapture",
	"sh":              "/bin/sh",
	"shutdown":        "/sbin/shutdown",
	"sysctl":          "/usr/sbin/sysctl",
	"system_profiler": "/usr/sbin/system_profiler",
	"sysadminctl":     "/usr/sbin/sysadminctl",
	"tcpdump":         "/usr/sbin/tcpdump",
}

// plausiblePath turns a bare leaf into somewhere a binary of that name actually lives.
//
// `Image|endswith: '/osascript'` is satisfied by the literal itself, but `/osascript` is not a path any macOS host reports, and
// these fixtures are read as examples of the telemetry a rule is about. Extended only for endswith/contains, where adding to the
// left cannot break the match; an exact match is left exactly as written.
//
// A name carrying a space is an application, not a command in a bin directory, so it takes the bundle layout the hand-written
// Office fixture uses.
//
// A name that is ONLY whitespace belongs to space_after_filename, whose rule is about a masquerading executable whose path ends
// in a space. That one goes under /tmp: the default would have produced `/usr/bin/ `, and on a sealed system volume no attacker
// can create that file, so the sample would depict telemetry the platform cannot emit.
func plausiblePath(value, modifier string) string {
	extendable := strings.Contains(modifier, "endswith") || strings.Contains(modifier, "contains")
	leaf := strings.TrimPrefix(value, "/")
	known, isKnown := knownLocations[leaf]
	switch {
	case strings.HasPrefix(value, "/") && strings.Count(value, "/") > 1:
		return value // already a path, not a leaf
	case !extendable && strings.HasPrefix(value, "/"):
		return value // an exact match: extending it would break the comparison
	case isKnown:
		return known
	case strings.TrimSpace(leaf) == "":
		return "/tmp/fixture-subject" + leaf
	case strings.Contains(leaf, " "):
		return "/Applications/" + leaf + ".app/Contents/MacOS/" + leaf
	case strings.HasPrefix(value, "/"):
		return "/usr/bin" + value
	default:
		return "/usr/bin/" + value
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
