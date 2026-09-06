package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOverlongMarkers_ScopedToTouchedLines is what makes this gate shippable rather than a wedge.
//
// Several hundred over-long markers already exist in the tree. Gating on all of them would fail every pull request in the
// repository for a defect none of them introduced, which is a shape this repository has been bitten by: a check that fires on
// work someone did not do gets ignored, and then it reports nothing on the day it is right.
func TestOverlongMarkers_ScopedToTouchedLines(t *testing.T) {
	t.Parallel()

	markers := []Marker{
		{ID: "a/b/c", SourcePath: "server/new_test.go", SourceLine: 10, LineLen: MaxMarkerLineLen + 1},
		{ID: "a/b/d", SourcePath: "server/old_test.go", SourceLine: 20, LineLen: MaxMarkerLineLen + 40},
		{ID: "a/b/e", SourcePath: "server/new_test.go", SourceLine: 11, LineLen: MaxMarkerLineLen},
	}
	touched := map[string][]lineRange{"server/new_test.go": {{Start: 8, End: 12}}}

	got := OverlongMarkers(markers, touched)
	assert.Len(t, got, 1, "only the over-long marker on a line this branch touched is reported")
	assert.Equal(t, "a/b/c", got[0].ID)
}

// TestOverlongMarkers_Boundary pins where the limit falls. It is a maximum, so a line exactly at it complies; getting that
// backwards would fail lines that are already correct, which is the kind of gate contributors learn to ignore.
func TestOverlongMarkers_Boundary(t *testing.T) {
	t.Parallel()
	touched := map[string][]lineRange{"f.go": {{Start: 1, End: 1}}}

	cases := []struct {
		name     string
		lineLen  int
		reported bool
	}{
		{"one under the limit", MaxMarkerLineLen - 1, false},
		{"exactly at the limit", MaxMarkerLineLen, false},
		{"one over the limit", MaxMarkerLineLen + 1, true},
		{"well over the limit", MaxMarkerLineLen + 40, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := OverlongMarkers([]Marker{{SourcePath: "f.go", SourceLine: 1, LineLen: tc.lineLen}}, touched)
			assert.Equal(t, tc.reported, len(got) == 1, "%d characters", tc.lineLen)
		})
	}
}

// TestOverlongMarkers_NilTouchedReportsEverything covers the deliberate sweep: a caller that wants the whole backlog passes no
// scope. It is also what a future change paying the backlog down would use.
func TestOverlongMarkers_NilTouchedReportsEverything(t *testing.T) {
	t.Parallel()
	markers := []Marker{
		{ID: "a", SourcePath: "x.go", SourceLine: 1, LineLen: MaxMarkerLineLen + 1},
		{ID: "b", SourcePath: "y.go", SourceLine: 2, LineLen: MaxMarkerLineLen + 2},
	}
	assert.Len(t, OverlongMarkers(markers, nil), 2)
}

// TestOverlongMarkers_UntouchedFileIsIgnored is the same property from the file side: a branch that never opened a file is not
// answerable for the markers in it.
func TestOverlongMarkers_UntouchedFileIsIgnored(t *testing.T) {
	t.Parallel()
	markers := []Marker{{ID: "a", SourcePath: "untouched.go", SourceLine: 5, LineLen: MaxMarkerLineLen + 50}}
	assert.Empty(t, OverlongMarkers(markers, map[string][]lineRange{"other.go": {{Start: 1, End: 100}}}))
}

// TestScanFile_DoesNotCountACarriageReturn covers the CRLF checkout: a marker line of exactly the limit must not be reported as
// one over on a machine that differs from the author's only in checkout settings.
//
// It holds because bufio.ScanLines strips the carriage return before Text() returns, which is worth a test rather than a comment:
// review asserted the opposite and proposed trimming it here, and a redundant trim would have read as load-bearing to whoever
// touched this next. Measured before deciding, and the scanner is right.
func TestScanFile_DoesNotCountACarriageReturn(t *testing.T) {
	t.Parallel()

	// A marker line padded to exactly the limit, then delivered with CRLF endings.
	const id = "a/b/c"
	marker := "// spec:" + id
	line := marker + strings.Repeat(" ", MaxMarkerLineLen-len(marker))
	require.Len(t, line, MaxMarkerLineLen)

	markers, err := scanFile(strings.NewReader(line+"\r\n"), "f.go", false, nil, nil)
	require.NoError(t, err)
	require.Len(t, markers, 1)
	assert.Equal(t, MaxMarkerLineLen, markers[0].LineLen, "the carriage return is not part of the line's width")

	touched := map[string][]lineRange{"f.go": {{Start: 1, End: 1}}}
	assert.Empty(t, OverlongMarkers(markers, touched), "a compliant line must not be reported because of its line ending")
}

// TestMarkerPathKey_ComponentWise pins that a path is judged outside the scan root by its COMPONENTS, not by a string prefix.
//
// A file legitimately named "..checks.go" starts with two dots without being outside anything. Rejecting it would drop every
// marker in that file from the gate's scope silently, which is the failure this change exists to stop, arriving through the
// change itself. Review caught it.
func TestMarkerPathKey_ComponentWise(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	cases := []struct {
		name         string
		scanRoot     string
		repoRelative string
		want         string
		wantErr      bool
	}{
		{"a file under the root", root, "server/a_test.go", "server/a_test.go", false},
		{"a leading-dot filename is not a traversal", root, "server/..checks.go", "server/..checks.go", false},
		{"a dotted name in a directory position", root, "..checks/a_test.go", "..checks/a_test.go", false},
		{"scoped to a subtree, the path loses the prefix", filepath.Join(root, "server"), "server/a_test.go", "a_test.go", false},
		{"outside the scan root is reported", filepath.Join(root, "server"), "tools/a_test.go", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := markerPathKey(root, tc.scanRoot, tc.repoRelative)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
