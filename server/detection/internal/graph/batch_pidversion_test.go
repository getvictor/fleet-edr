package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/detection/api"
)

// TestImageRankGreaterSeparatesEqualStampsByPIDVersion covers the batch overlay's half of issue #724.
//
// The overlay and the store both answer "what was this PID running at this instant", so an ordering fixed in one and not the other
// makes the answer depend on whether the parent happened to be in the same batch as its child. That is the worst shape of bug in
// this area: it reproduces only under a batch boundary. These cases mirror the store's integration tests directly.
func TestImageRankGreaterSeparatesEqualStampsByPIDVersion(t *testing.T) {
	t.Parallel()

	const forkAt = int64(100)
	row := func(seq int64, path string, pidversion *uint32) *procRow {
		return &procRow{proc: api.Process{PID: 500, Path: path, ForkTimeNs: forkAt, PIDVersion: pidversion}, seq: seq}
	}
	ptr := func(v uint32) *uint32 { return &v }

	cases := []struct {
		name string
		a, b *procRow
		want bool
	}{
		{
			// Both fork-only and sharing a stamp, so nothing before the tie-break separates them. seq (ingest order) favours b,
			// kernel generation favours a, and kernel generation must win: issue #714 established ingest order is unreliable.
			name: "the higher kernel generation outranks a later-ingested lower one",
			a:    row(1, "/newer", ptr(9)),
			b:    row(2, "/older", ptr(7)),
			want: true,
		},
		{
			name: "a row carrying kernel evidence outranks one carrying none",
			a:    row(1, "/known", ptr(4)),
			b:    row(2, "/unknown", nil),
			want: true,
		},
		{
			name: "a row carrying none loses to one that does, whichever way round they are ingested",
			a:    row(2, "/unknown", nil),
			b:    row(1, "/known", ptr(4)),
			want: false,
		},
		{
			// Neither carries evidence, so there is nothing better than ingest order left to fall back on.
			name: "with no pidversion on either side the sequence still breaks the tie",
			a:    row(2, "/second", nil),
			b:    row(1, "/first", nil),
			want: true,
		},
		{
			// Equal pidversions are duplicate rows for ONE generation (199 of the 225 equal-stamp groups measured on the dev
			// database), which is the issue #717 defect rather than a collision an ordering can resolve.
			name: "equal pidversions fall through to the sequence",
			a:    row(2, "/second", ptr(5)),
			b:    row(1, "/first", ptr(5)),
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// An instant before any exec, so the applied-image branches tie and the tie-break under test is what decides.
			assert.Equal(t, tc.want, imageRankGreater(tc.a, tc.b, forkAt+1))
		})
	}
}
