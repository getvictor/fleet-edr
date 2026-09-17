package watchedpaths

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/catchup"
	"github.com/fleetdm/edr/server/rules/api"
)

func TestNeedsSet(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	updated := now.Add(-2 * time.Hour)
	set := api.WatchedPathSet{Version: 4, UpdatedAt: &updated}
	enrolled := api.WatchedPathEnrollment{HostID: "h", EnrolledAt: now.Add(-24 * time.Hour)}
	payload := func(version int64) []byte {
		b, _ := json.Marshal(api.SetWatchedPathsPayload{Version: version, Epoch: updated.UnixMicro(), Paths: []api.WatchedPath{}})
		return b
	}
	queued := func(version int64, status string, created, completed time.Time) api.WatchedPathCommand {
		return api.WatchedPathCommand{Payload: payload(version), Status: status, CreatedAt: created, CompletedAt: completed}
	}
	at := now.Add
	hourAgo := now.Add(-time.Hour)

	cases := []struct {
		name string
		cmd  api.WatchedPathCommand
		want bool
	}{
		{"never sent one", api.WatchedPathCommand{}, true},
		{"sent an older version", queued(3, "completed", hourAgo, at(-time.Hour)), true},
		{"same version, different epoch", api.WatchedPathCommand{
			Payload: []byte(`{"version":4,"epoch":1,"paths":[]}`), Status: "completed", CreatedAt: hourAgo,
		}, true},
		{"queued at the same instant the host enrolled", queued(4, "completed", enrolled.EnrolledAt, at(-time.Hour)), true},
		{"payload it cannot read", api.WatchedPathCommand{Payload: []byte(`{`), Status: "completed", CreatedAt: hourAgo}, true},
		{"queued before the host last enrolled", queued(4, "completed", now.Add(-48*time.Hour), at(-47*time.Hour)), true},
		{"expired undelivered", queued(4, "expired", hourAgo, at(-time.Minute)), true},
		{"cancelled", queued(4, "cancelled", hourAgo, at(-time.Minute)), true},
		{"failed long enough ago to retry", queued(4, "failed", now.Add(-8*time.Hour), at(-7*time.Hour)), true},
		{"failed exactly six hours ago", queued(4, "failed", now.Add(-7*time.Hour), at(-catchup.FailedRetryAfter)), true},
		{"failed just under six hours ago", queued(4, "failed", now.Add(-7*time.Hour), at(-catchup.FailedRetryAfter+time.Second)), false},
		{"failed recently", queued(4, "failed", hourAgo, at(-time.Hour)), false},
		{"pending", queued(4, "pending", hourAgo, time.Time{}), false},
		{"acked", queued(4, "acked", hourAgo, time.Time{}), false},
		{"completed", queued(4, "completed", hourAgo, at(-time.Hour)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, needsSet(tc.cmd, enrolled, set, now))
		})
	}
}
