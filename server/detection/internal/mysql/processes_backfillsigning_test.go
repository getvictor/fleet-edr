package mysql_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
)

// TestBackfillSnapshotSigning pins the conditional write behind completing a snapshot row's signature: it lands on an open row with no
// signature, and leaves alone a row that already has one or that exited after the batch read it. The graph builder decides which rows
// qualify from its preloaded view, so these guards are what keep a concurrent TTL exit or an earlier backfill from being overwritten.
// Both write paths are checked: the batch flush and the store's direct call.
//
// spec:server-process-graph-builder/a-later-snapshot-completes-a-missing-signature/a-row-that-exits-meanwhile-is-not-written
func TestBackfillSnapshotSigning(t *testing.T) {
	t.Parallel()
	signed := api.NullRawJSON(`{"team_id":"","signing_id":"com.apple.mds","flags":637606673,"is_platform_binary":true}`)
	earlier := api.NullRawJSON(`{"team_id":"","signing_id":"com.apple.mds.first","flags":0,"is_platform_binary":true}`)
	exitNs := int64(2_000_000_000)

	cases := []struct {
		name    string
		start   api.NullRawJSON // the row's signature before the backfill
		exited  bool            // the row exited after the batch preloaded it
		wantSID string          // signing_id afterwards, "" for none
	}{
		{name: "an open unsigned row takes the signature", wantSID: "com.apple.mds"},
		{name: "a row that already has a signature keeps it", start: earlier, wantSID: "com.apple.mds.first"},
		{name: "a row that exited meanwhile is not written", exited: true},
	}
	writers := []struct {
		name  string
		write func(ctx context.Context, s *mysql.Store, rowID int64) error
	}{
		{"batch flush", func(ctx context.Context, s *mysql.Store, rowID int64) error {
			return s.FlushProcessBatch(ctx, mysql.ProcessBatchPlan{
				SigningBackfills: []mysql.SigningBackfill{{ID: rowID, CodeSigning: signed}},
			})
		}},
		{"direct", func(ctx context.Context, s *mysql.Store, rowID int64) error {
			return s.BackfillSnapshotSigning(ctx, "h-backfill", 4001, rowID, signed)
		}},
	}
	for _, w := range writers {
		for _, tc := range cases {
			t.Run(w.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				s := newTestStore(t)
				ctx := t.Context()
				execNs := int64(1_000_000_000)
				row := api.Process{HostID: "h-backfill", PID: 4001, Path: "/System/mds", ForkTimeNs: execNs, ExecTimeNs: &execNs,
					IsSnapshot: true, CodeSigning: tc.start}
				id, err := s.InsertProcess(ctx, row)
				require.NoError(t, err)
				if tc.exited {
					_, err := s.DB().ExecContext(ctx, `UPDATE processes SET exit_time_ns = ? WHERE id = ?`, exitNs, id)
					require.NoError(t, err)
				}

				require.NoError(t, w.write(ctx, s, id))

				var got api.NullRawJSON
				require.NoError(t, s.DB().GetContext(ctx, &got, `SELECT code_signing FROM processes WHERE id = ?`, id))
				if tc.wantSID == "" {
					assert.Empty(t, got)
					return
				}
				var cs struct {
					SigningID string `json:"signing_id"`
				}
				require.NoError(t, json.Unmarshal(got, &cs))
				assert.Equal(t, tc.wantSID, cs.SigningID)
			})
		}
	}
}
