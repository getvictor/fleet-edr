package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// runReport implements `spectrace report --format=md [--output FILE]`. The Markdown coverage matrix has one row per scenario
// and one column per test layer (L0..L6), with each cell listing the markers (file:line links) that cover the scenario at
// that layer. The matrix is the v2 deliverable from issue #233; the data it presents is the same canonical+markers set the
// check subcommand already loads, so this function is a pure presentation layer with no spec-parsing or marker-scanning
// duplication. Exit codes: 0 on a clean render, 2 on IO / usage error. The subcommand does NOT gate (unlike check
// --strict); it is a reporting tool for humans + PR comments. CI can grep the rendered matrix for "uncovered" rows if a
// gate is needed.
func runReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	specsDir := fs.String("specs-dir", defaultSpecsDir, "root of the openspec/specs tree")
	changesDir := fs.String("changes-dir", defaultChangesDir, "openspec/changes tree; in-flight proposal scenarios are valid marker targets")
	rootDir := fs.String("root", defaultRootDir, "root of the source tree to scan for markers")
	format := fs.String("format", "md", "output format (currently only `md` is supported)")
	output := fs.String("output", "", "write to FILE instead of stdout")
	normativeOnly := fs.Bool("normative-only", false,
		"restrict the matrix to scenarios whose parent requirement contains SHALL or MUST")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *format != "md" {
		fmt.Fprintf(os.Stderr, "spectrace report: unsupported --format %q (only `md` is supported)\n", *format)
		return 2
	}

	// Promote --specs-dir / --root to repo-root-relative when cwd doesn't have them; matches the runCheck shape.
	setFlags := userSetFlagNames(fs)
	*specsDir = resolvePathFlag(*specsDir, setFlags["specs-dir"])
	*changesDir = resolvePathFlag(*changesDir, setFlags["changes-dir"])
	*rootDir = resolvePathFlag(*rootDir, setFlags["root"])

	scenarios, _, markers, exitCode := loadScenariosAndMarkers(*specsDir, *changesDir, *rootDir)
	if exitCode != 0 {
		return exitCode
	}

	w, closer, err := openReportWriter(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spectrace report: %v\n", err)
		return 2
	}
	defer closer()

	// Buffer the writer so a single Flush surfaces any IO error (broken pipe, disk full) instead of silently truncating
	// the matrix. CodeRabbit flagged the unchecked write on PR #281: with raw os.Stdout, `spectrace report | head` would
	// SIGPIPE mid-stream and exit 0; the buffered Flush returns the EPIPE so the caller sees exit 2.
	bw := bufio.NewWriter(w)
	renderMarkdownMatrix(bw, scenarios, markers, *normativeOnly)
	if err := bw.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "spectrace report: write output: %v\n", err)
		return 2
	}
	return 0
}

// loadScenariosAndMarkers is the shared specs+markers load path used by report and (in --new-code mode) check. Returns
// (scenarios, markers, exitCode); when exitCode != 0 the error has already been written to stderr and the caller should
// return it directly. Kept here rather than in main.go because report.go is the first consumer; check predates this and
// inlines the same three calls. A future refactor could fold them, but the diff would be wider than the deduplication.
func loadScenariosAndMarkers(specsDir, changesDir, rootDir string) ([]Scenario, map[string]struct{}, []Marker, int) {
	scenarios, err := ParseAllSpecs(specsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spectrace: parse specs:", err)
		return nil, nil, nil, 2
	}
	canonical, dupErr := buildCanonicalSet(scenarios)
	if dupErr != nil {
		fmt.Fprintln(os.Stderr, "spectrace:", dupErr)
		return nil, nil, nil, 2
	}
	// Union the live canonical IDs with the WIP IDs from change proposals to form the reference-valid set: the set a
	// marker's ID must be in to count as a real reference rather than a dangling one. Live scenarios alone drive coverage
	// and the --strict gate (see runCheck); WIP IDs only widen what a marker is allowed to point at.
	wipIDs, err := parseChangeScenarioIDs(changesDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spectrace: parse change specs:", err)
		return nil, nil, nil, 2
	}
	referenceValid := make(map[string]struct{}, len(canonical)+len(wipIDs))
	for id := range canonical {
		referenceValid[id] = struct{}{}
	}
	for id := range wipIDs {
		referenceValid[id] = struct{}{}
	}
	markers, err := ScanMarkers(rootDir, referenceValid)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spectrace: scan markers:", err)
		return nil, nil, nil, 2
	}
	return scenarios, referenceValid, markers, 0
}

// parseChangeScenarioIDs returns the set of canonical scenario IDs declared in in-flight OpenSpec change proposals under
// changesDir (openspec/changes/<change>/specs/<capability>/spec.md). Unlike the live specs these IDs are NOT run through
// buildCanonicalSet's duplicate detection: a MODIFIED requirement in a proposal intentionally repeats a live scenario
// heading (and two proposals may touch the same capability), so collisions are expected and collapse harmlessly into the
// set. A missing or empty changesDir yields an empty set so a repo with no in-flight proposals behaves exactly as before.
func parseChangeScenarioIDs(changesDir string) (map[string]struct{}, error) {
	ids := make(map[string]struct{})
	if changesDir == "" {
		return ids, nil
	}
	info, statErr := os.Stat(changesDir)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return ids, nil
		}
		return nil, statErr
	}
	if !info.IsDir() {
		return ids, nil
	}
	scenarios, err := ParseAllSpecs(changesDir)
	if err != nil {
		return nil, err
	}
	for _, s := range scenarios {
		ids[s.ID] = struct{}{}
	}
	return ids, nil
}

// openReportWriter returns (writer, cleanup, error). When path is empty the writer is stdout and the cleanup is a no-op.
// When path is non-empty the writer is a newly-created file whose cleanup closes it. Errors from Close are reported via
// stderr at cleanup time because the report renderer has already returned by then.
func openReportWriter(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path) //nolint:gosec // path comes from a --output flag the operator supplies
	if err != nil {
		return nil, nil, fmt.Errorf("open --output %s: %w", path, err)
	}
	cleanup := func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "spectrace report: close %s: %v\n", path, cerr)
		}
	}
	return f, cleanup, nil
}

// renderMarkdownMatrix writes a single Markdown table to w with one row per scenario and one column per layer. The columns
// are L0..L6 always, plus an "Other" column at the right when at least one marker classifies as LayerOther. Cell content
// is a comma-separated list of `[basename:line](path)` Markdown links pointing at the marker source. The header summarises
// total scenarios, normative count, and the per-layer marker totals so a reader skimming the file gets the gestalt before
// scanning rows.
func renderMarkdownMatrix(w io.Writer, scenarios []Scenario, markers []Marker, normativeOnly bool) {
	coverage := indexMarkersByScenario(markers)
	includeOther := matrixHasOtherMarkers(scenarios, coverage, normativeOnly)
	cols := matrixColumns(includeOther)

	writeMatrixHeader(w, scenarios, markers, normativeOnly)
	writeColumnHeaders(w, cols)
	writeMatrixRows(w, scenarios, coverage, cols, normativeOnly)
}

// matrixHasOtherMarkers reports whether the LayerOther column needs to render. We omit it when no scenario has a non-test
// marker so the standard matrix stays compact for the bulk of specs. The normativeOnly filter is honoured so the column
// decision matches the row set.
func matrixHasOtherMarkers(scenarios []Scenario, coverage map[string][]Marker, normativeOnly bool) bool {
	for _, s := range scenarios {
		if normativeOnly && !s.Normative {
			continue
		}
		for _, m := range coverage[s.ID] {
			if m.Layer == LayerOther {
				return true
			}
		}
	}
	return false
}

// matrixColumns returns the layer set rendered as columns, in stable left-to-right order. When includeOther is true the
// LayerOther column is appended at the right.
func matrixColumns(includeOther bool) []Layer {
	cols := append([]Layer(nil), allTestLayers[:]...)
	if includeOther {
		cols = append(cols, LayerOther)
	}
	return cols
}

// writeMatrixHeader writes the title + summary block above the table. The per-layer marker totals are derived from the full
// marker slice (not the coverage map) so invalid-reference markers also contribute, giving an honest "where do the markers
// live" view independent of whether they line up with a canonical ID.
func writeMatrixHeader(w io.Writer, scenarios []Scenario, markers []Marker, normativeOnly bool) {
	totalNormative := 0
	for _, s := range scenarios {
		if s.Normative {
			totalNormative++
		}
	}
	fmt.Fprintln(w, "# spectrace coverage matrix")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- Scenarios total: %d (%d normative, %d advisory)\n",
		len(scenarios), totalNormative, len(scenarios)-totalNormative)
	if normativeOnly {
		fmt.Fprintln(w, "- Filter: `--normative-only` (advisory scenarios omitted)")
	}
	fmt.Fprintln(w, "- Markers by layer:")
	for _, l := range allTestLayers {
		fmt.Fprintf(w, "  - %s: %d\n", l.Label(), countMarkersAtLayer(markers, l))
	}
	if otherCount := countMarkersAtLayer(markers, LayerOther); otherCount > 0 {
		fmt.Fprintf(w, "  - Other: %d\n", otherCount)
	}
	fmt.Fprintln(w)
}

func countMarkersAtLayer(markers []Marker, l Layer) int {
	n := 0
	for _, m := range markers {
		if m.Layer == l {
			n++
		}
	}
	return n
}

func writeColumnHeaders(w io.Writer, cols []Layer) {
	headers := make([]string, 0, len(cols)+1)
	headers = append(headers, "Scenario")
	for _, l := range cols {
		headers = append(headers, l.Label())
	}
	fmt.Fprintln(w, "| "+strings.Join(headers, " | ")+" |")
	dividers := make([]string, len(headers))
	for i := range dividers {
		dividers[i] = "---"
	}
	fmt.Fprintln(w, "|"+strings.Join(dividers, "|")+"|")
}

func writeMatrixRows(w io.Writer, scenarios []Scenario, coverage map[string][]Marker,
	cols []Layer, normativeOnly bool,
) {
	for _, s := range scenarios {
		if normativeOnly && !s.Normative {
			continue
		}
		cells := make([]string, 0, len(cols)+1)
		cells = append(cells, escapeMarkdownPipe(s.ID))
		for _, l := range cols {
			cells = append(cells, renderCell(coverage[s.ID], l))
		}
		fmt.Fprintln(w, "| "+strings.Join(cells, " | ")+" |")
	}
}

// indexMarkersByScenario groups markers by their canonical ID. Synthetic Swift IDs (`swift:` / `swift-ambiguous:` from
// resolveSwiftMarker) are dropped because they cannot match any scenario row. Other invalid references (a typo'd ID, a
// stale slug after a spec rename) are still indexed under their literal ID — they don't render because the row iteration
// uses the canonical scenario list, not this map's key set. The check subcommand reports those typo'd markers separately
// as invalid references, so leaving them in the map here is harmless and avoids re-threading the canonical set through
// the report path. Within a group, markers are sorted by (Layer, SourcePath, SourceLine) so cell rendering is
// deterministic. Copilot's comment-vs-behavior nit on PR #281.
func indexMarkersByScenario(markers []Marker) map[string][]Marker {
	out := make(map[string][]Marker)
	for _, m := range markers {
		if strings.HasPrefix(m.ID, "swift:") || strings.HasPrefix(m.ID, "swift-ambiguous:") {
			continue
		}
		out[m.ID] = append(out[m.ID], m)
	}
	for id := range out {
		sort.Slice(out[id], func(i, j int) bool {
			a, b := out[id][i], out[id][j]
			if a.Layer != b.Layer {
				return a.Layer < b.Layer
			}
			if a.SourcePath != b.SourcePath {
				return a.SourcePath < b.SourcePath
			}
			return a.SourceLine < b.SourceLine
		})
	}
	return out
}

// renderCell formats every marker covering the scenario at the given layer as a comma-separated list of Markdown links.
// Empty cells render as an empty string; the table row uses ` | ` separators so a missing entry is visually distinct.
func renderCell(markers []Marker, l Layer) string {
	var links []string
	for _, m := range markers {
		if m.Layer != l {
			continue
		}
		links = append(links, formatMarkerLink(m))
	}
	if len(links) == 0 {
		return ""
	}
	return strings.Join(links, ", ")
}

// formatMarkerLink builds `[basename:line](path)` for a marker. The path is the same forward-slash repo-relative form
// stored on the Marker, which Markdown renderers on GitHub resolve relative to the file containing the table; for stdout
// previews the link is still a clickable hint for IDE users.
func formatMarkerLink(m Marker) string {
	base := m.SourcePath
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	return fmt.Sprintf("[%s:%d](%s#L%d)", base, m.SourceLine, m.SourcePath, m.SourceLine)
}

// escapeMarkdownPipe replaces literal `|` with the HTML entity so a pipe character inside a scenario ID does not break the
// table row. Canonical IDs are slug-only so this is defensive; if a non-canonical row ever gets rendered (e.g. a future
// `--include-invalid` flag), the escape keeps the table well-formed.
func escapeMarkdownPipe(s string) string {
	return strings.ReplaceAll(s, "|", "&#124;")
}
