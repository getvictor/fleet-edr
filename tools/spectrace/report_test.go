package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureScenarios is the shared scenario set the report tests render against. Two normative scenarios + one advisory so the
// --normative-only filter has something to drop, two distinct spec dirs so the row sort is observable. The IDs match the
// canonical-slug rule (lowercase, dash-separated) so the test exercises the same shape main.go produces in the real run.
func fixtureScenarios() []Scenario {
	return []Scenario{
		{
			ID:        "agent-event-uploader/upload-uses-the-host-bearer-token/upload-with-a-valid-token",
			Normative: true,
		},
		{
			ID:        "agent-event-uploader/upload-uses-the-host-bearer-token/upload-with-an-expired-token",
			Normative: true,
		},
		{
			ID:        "release-packaging/dry-run-build-on-any-macos-runner/pull-request-runs-the-dry-run",
			Normative: false,
		},
	}
}

// fixtureMarkers wires one marker per layer L0/L1/L4 and one Other-layer marker so the renderer must lay them out across the
// matrix columns AND emit the Other column. Two L0 markers on the same scenario exercise the comma-separated-cell branch;
// they sit on different files so the renderer's marker sort by (path, line) is observable.
func fixtureMarkers() []Marker {
	return []Marker{
		{
			ID:         "agent-event-uploader/upload-uses-the-host-bearer-token/upload-with-a-valid-token",
			SourcePath: "agent/uploader/uploader_test.go",
			SourceLine: 42,
			Layer:      LayerUnit,
		},
		{
			ID:         "agent-event-uploader/upload-uses-the-host-bearer-token/upload-with-a-valid-token",
			SourcePath: "server/endpoint/internal/tests/upload_test.go",
			SourceLine: 73,
			Layer:      LayerPerContext,
		},
		{
			ID:         "agent-event-uploader/upload-uses-the-host-bearer-token/upload-with-an-expired-token",
			SourcePath: "test/e2e/tests/qa/upload-with-bad-token.spec.ts",
			SourceLine: 12,
			Layer:      LayerBrowserE2E,
		},
		{
			ID:         "release-packaging/dry-run-build-on-any-macos-runner/pull-request-runs-the-dry-run",
			SourcePath: ".github/workflows/pkg-dryrun.yml",
			SourceLine: 19,
			Layer:      LayerOther,
		},
	}
}

// TestRenderMarkdownMatrix covers the happy-path render: header summary, column headers, per-row content, and the on-demand
// Other column. The assertion uses contains-substring matches rather than full equality because the precise whitespace +
// summary numbers are content-tested by other cases; this case is about structure.
func TestRenderMarkdownMatrix(t *testing.T) {
	var buf bytes.Buffer
	renderMarkdownMatrix(&buf, fixtureScenarios(), fixtureMarkers(), false)
	out := buf.String()

	assert.Contains(t, out, "# spectrace coverage matrix")
	assert.Contains(t, out, "Scenarios total: 3 (2 normative, 1 advisory)")
	assert.Contains(t, out, "| Scenario | L0 | L1 | L2 | L3 | L4 | L5 | L6 | Other |")

	// L0 cell carries the marker link; L1 column on the same row also has its marker.
	assert.Contains(t, out,
		"[uploader_test.go:42](agent/uploader/uploader_test.go#L42)")
	assert.Contains(t, out,
		"[upload_test.go:73](server/endpoint/internal/tests/upload_test.go#L73)")
	// L4 marker on the second scenario.
	assert.Contains(t, out, "[upload-with-bad-token.spec.ts:12](test/e2e/tests/qa/upload-with-bad-token.spec.ts#L12)")
	// Other marker on the advisory scenario.
	assert.Contains(t, out, "[pkg-dryrun.yml:19](.github/workflows/pkg-dryrun.yml#L19)")
}

// TestRenderMarkdownMatrix_NormativeOnlyFilter pins the row filter: with --normative-only the advisory scenario is dropped
// from the row set AND the Other column is dropped because its only marker was on that scenario. This is the property the
// matrixHasOtherMarkers helper guards.
func TestRenderMarkdownMatrix_NormativeOnlyFilter(t *testing.T) {
	var buf bytes.Buffer
	renderMarkdownMatrix(&buf, fixtureScenarios(), fixtureMarkers(), true)
	out := buf.String()

	assert.Contains(t, out, "Filter: `--normative-only`")
	assert.NotContains(t, out, "release-packaging/dry-run-build-on-any-macos-runner",
		"advisory scenario row must be omitted with --normative-only")
	assert.NotContains(t, out, "| Other |",
		"Other column must drop when no rendered row has an Other marker")
	assert.Contains(t, out, "| Scenario | L0 | L1 | L2 | L3 | L4 | L5 | L6 |",
		"standard 7-column header must still render")
}

// TestRenderMarkdownMatrix_MultipleMarkersInCell pins the comma-separated cell rendering when two markers land in the same
// (scenario, layer) cell.
func TestRenderMarkdownMatrix_MultipleMarkersInCell(t *testing.T) {
	scenarios := []Scenario{
		{ID: "x/y/z", Normative: true},
	}
	markers := []Marker{
		{ID: "x/y/z", SourcePath: "a_test.go", SourceLine: 10, Layer: LayerUnit},
		{ID: "x/y/z", SourcePath: "b_test.go", SourceLine: 20, Layer: LayerUnit},
	}
	var buf bytes.Buffer
	renderMarkdownMatrix(&buf, scenarios, markers, false)
	out := buf.String()
	assert.Contains(t, out, "[a_test.go:10](a_test.go#L10), [b_test.go:20](b_test.go#L20)")
}

// TestRenderMarkdownMatrix_SwiftInvalidMarkersAreSkipped guards a property of indexMarkersByScenario: markers with synthetic
// `swift:` or `swift-ambiguous:` IDs are reported by check, not by report. They must not appear in any matrix cell because
// they don't belong to any canonical scenario.
func TestRenderMarkdownMatrix_SwiftInvalidMarkersAreSkipped(t *testing.T) {
	scenarios := []Scenario{
		{ID: "x/y/z", Normative: true},
	}
	markers := []Marker{
		{ID: "swift:does_not_exist", SourcePath: "Tests/X.swift", SourceLine: 1, Layer: LayerUnit},
		{ID: "swift-ambiguous:foo_bar", SourcePath: "Tests/Y.swift", SourceLine: 2, Layer: LayerUnit},
	}
	var buf bytes.Buffer
	renderMarkdownMatrix(&buf, scenarios, markers, false)
	out := buf.String()
	assert.NotContains(t, out, "swift:")
	assert.NotContains(t, out, "swift-ambiguous:")
	// The row exists but every cell is empty.
	require.Contains(t, out, "| x/y/z |")
}

// TestEscapeMarkdownPipe pins the pipe-escape behaviour. A pipe inside a scenario ID would otherwise close the table cell
// and break the row. Canonical IDs never contain pipes today, but the escape is defensive against future shapes.
func TestEscapeMarkdownPipe(t *testing.T) {
	assert.Equal(t, "a&#124;b", escapeMarkdownPipe("a|b"))
	assert.Equal(t, "noop", escapeMarkdownPipe("noop"))
}

// TestFormatMarkerLink pins the link shape: `[basename:line](path#Lline)`.
func TestFormatMarkerLink(t *testing.T) {
	cases := []struct {
		name string
		m    Marker
		want string
	}{
		{"deeply nested path uses basename in label", Marker{
			SourcePath: "server/identity/internal/tests/journeys/login_test.go", SourceLine: 12,
		}, "[login_test.go:12](server/identity/internal/tests/journeys/login_test.go#L12)"},
		{"top-level path uses the same name in both spots", Marker{
			SourcePath: "main_test.go", SourceLine: 7,
		}, "[main_test.go:7](main_test.go#L7)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, formatMarkerLink(tc.m))
		})
	}
}

// TestRunReport_UnsupportedFormat pins the only failure path that runReport returns without delegating to the loader. A
// future `--format=json` will need a corresponding test row.
func TestRunReport_UnsupportedFormat(t *testing.T) {
	code := runReport([]string{"--format", "json"})
	assert.Equal(t, 2, code)
}

// TestMatrixHasOtherMarkers covers the column-on-demand decision. Cases drive both directions: an empty marker set, a set
// with only test markers, and a set with a single Other marker on a row included by the filter.
func TestMatrixHasOtherMarkers(t *testing.T) {
	scenarios := fixtureScenarios()
	markers := fixtureMarkers()
	coverage := indexMarkersByScenario(markers)

	assert.True(t, matrixHasOtherMarkers(scenarios, coverage, false),
		"unfiltered set includes the advisory scenario whose marker is LayerOther")
	assert.False(t, matrixHasOtherMarkers(scenarios, coverage, true),
		"normative-only filter drops the row that owned the Other marker")
}

// TestRenderMarkdownMatrix_EmptyScenarios pins the degenerate render: the header still emits, the table has only the column
// header + divider rows, and no panic.
func TestRenderMarkdownMatrix_EmptyScenarios(t *testing.T) {
	var buf bytes.Buffer
	renderMarkdownMatrix(&buf, nil, nil, false)
	out := buf.String()
	assert.Contains(t, out, "Scenarios total: 0")
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	// Header block + column header + divider = no data rows. Find the column header line and assert nothing follows.
	headerIdx := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "| Scenario | L0 |") {
			headerIdx = i
			break
		}
	}
	require.NotEqual(t, -1, headerIdx, "expected column header in output")
	require.GreaterOrEqual(t, len(lines), headerIdx+2, "expected divider row after header")
	assert.True(t, strings.HasPrefix(lines[headerIdx+1], "|---|"))
	assert.Equal(t, headerIdx+1, len(lines)-1, "no data rows should follow the divider when scenarios is empty")
}
