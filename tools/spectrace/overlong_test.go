package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

// TestOverlongMarkers_AtTheLimitIsFine pins the boundary. The limit is a maximum, so a line exactly at it complies, and getting
// this backwards would fail lines that are already correct.
func TestOverlongMarkers_AtTheLimitIsFine(t *testing.T) {
	t.Parallel()
	touched := map[string][]lineRange{"f.go": {{Start: 1, End: 1}}}
	assert.Empty(t, OverlongMarkers([]Marker{{SourcePath: "f.go", SourceLine: 1, LineLen: MaxMarkerLineLen}}, touched))
	assert.Len(t, OverlongMarkers([]Marker{{SourcePath: "f.go", SourceLine: 1, LineLen: MaxMarkerLineLen + 1}}, touched), 1)
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
