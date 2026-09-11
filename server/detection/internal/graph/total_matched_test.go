package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// spec:server-rest-api/per-host-process-forest/counting-stops-at-its-bound-rather-than-scanning-the-whole-window
//
// TestResolveTotalMatched enumerates what the count can establish against what the read already proved. Every case here is one a
// live database will not produce on demand (a budget expiry, a retention prune landing between two statements), which is why the
// composition is a function rather than a branch inside BuildTree.
//
// The first row is the defect review caught: a count that gave up returned zero, BuildTree floored that to Returned, and the
// truncation flag was then derived from Returned < TotalMatched, which is false. The page shipped with total_matched_capped=true
// and truncated=false, so the UI suppressed the notice and presented an unverified full page as complete. Truncation now comes
// from the read's lookahead row, and this function's job is only to keep the NUMBER honest.
func TestResolveTotalMatched(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		returned   int64
		total      int64
		capped     bool
		wantTotal  int64
		wantCapped bool
	}{
		{
			name: "count gave up on its budget", returned: 5000, total: 0, capped: true,
			wantTotal: 5000, wantCapped: true,
		},
		{
			name: "count stopped at its bound", returned: 5000, total: 10000, capped: true,
			wantTotal: 10000, wantCapped: true,
		},
		{
			name: "count is exact and above the page", returned: 2000, total: 7431, capped: false,
			wantTotal: 7431, wantCapped: false,
		},
		{
			name: "retention pruned rows between the two statements", returned: 2000, total: 1998, capped: false,
			wantTotal: 2000, wantCapped: true,
		},
		{
			name: "count lands exactly on the page", returned: 2000, total: 2000, capped: false,
			wantTotal: 2000, wantCapped: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			total, capped := resolveTotalMatched(tc.returned, tc.total, tc.capped)
			assert.Equal(t, tc.wantTotal, total)
			assert.Equal(t, tc.wantCapped, capped)
			assert.GreaterOrEqual(t, total, tc.returned,
				"the rows in hand are always a floor: a denominator below the numerator reads as showing more than matched")
			assert.False(t, total == tc.returned && !capped,
				"the lookahead proved a row beyond the page, so reporting the page size as an exact total would read \"showing N of N\" under a truncation notice")
		})
	}
}
