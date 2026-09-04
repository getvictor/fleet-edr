package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
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

// spec:server-process-graph-builder/a-process-lookup-at-an-instant-returns-the-image-that-was-running-then/a-parent-that-re-executed-after-the-fork-still-reports-the-forking-image
//
// TestBatchGetProcessByPIDResolvesTheImageAtTheInstant is the overlay's half of issue #799, and the case that was missing when the
// store's half was fixed.
//
// Rules read the graph through this overlay, so it is the production path and the store's query is what a cold read falls back to.
// An ordering fixed in one and not the other makes the answer depend on whether the parent happened to be in the same batch as its
// child, which is the shape of bug that reproduces only at a batch boundary. Review caught exactly that on the store-only fix, and
// mutating this back to the fork-and-sequence ranking still passed every test in this package until this one existed.
func TestBatchGetProcessByPIDResolvesTheImageAtTheInstant(t *testing.T) {
	t.Parallel()

	const (
		host       = "h"
		pid        = 7100
		forkedAt   = int64(1000)
		reExecedAt = int64(2000)
	)
	first, second := forkedAt, reExecedAt
	// One pid, two generations sharing a fork time, which is what a re-exec produces. The later generation has the higher
	// sequence, which is the ordering that produced the wrong answer.
	attacker := &procRow{proc: api.Process{HostID: host, PID: pid, Path: "/bin/attacker", ForkTimeNs: forkedAt, ExecTimeNs: &first}, seq: 1}
	benign := &procRow{seq: 2, proc: api.Process{
		HostID: host, PID: pid, Path: "/bin/benign", ForkTimeNs: forkedAt, ExecTimeNs: &second,
	}}

	s := &batchSession{
		rows:  []*procRow{attacker, benign},
		byKey: map[mysql.HostPID][]*procRow{{HostID: host, PID: pid}: {attacker, benign}},
	}

	cases := []struct {
		name string
		at   int64
		want string
	}{
		{"at the fork instant, the forking image", forkedAt, "/bin/attacker"},
		{"between the fork and the re-exec, still the forking image", reExecedAt - 1, "/bin/attacker"},
		{"at the re-exec, the adopted image", reExecedAt, "/bin/benign"},
		{"after the re-exec, the adopted image", reExecedAt + 1_000_000, "/bin/benign"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := s.GetProcessByPID(t.Context(), host, pid, tc.at)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tc.want, got.Path, "the overlay must answer what the store answers, or the result depends on batching")
		})
	}

	t.Run("a process between its fork and its first exec is still found", func(t *testing.T) {
		t.Parallel()
		// The regression the store's first fix introduced: a first exec updates the fork row in place, so such a row's image
		// start lies in the future, and the parent lookups ask at a child's fork time which can fall in that window.
		execAt := int64(2000)
		row := &procRow{seq: 1, proc: api.Process{
			HostID: host, PID: 7300, Path: "/bin/preexec", ForkTimeNs: 1000, ExecTimeNs: &execAt,
		}}
		session := &batchSession{
			rows:  []*procRow{row},
			byKey: map[mysql.HostPID][]*procRow{{HostID: host, PID: 7300}: {row}},
		}
		got, err := session.GetProcessByPID(t.Context(), host, 7300, 1500)
		require.NoError(t, err)
		require.NotNil(t, got, "a process that exists at the instant asked about must be found, image started or not")
		assert.Equal(t, "/bin/preexec", got.Path)
	})
}
