//go:build integration

package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
)

const watchedPathsRoute = "/api/v1/detection-config/watched-paths"

type watchedPathsBody struct {
	rulesapi.WatchedPathSet
	BuiltIn  []rulesapi.WatchedPath `json:"built_in"`
	MaxPaths int                    `json:"max_paths"`
}

type replaceWatchedPathsBody struct {
	Set          rulesapi.WatchedPathSet `json:"set"`
	FanoutHosts  int                     `json:"fanout_hosts"`
	FanoutFailed int                     `json:"fanout_failed"`
}

func (r *appControlRig) watchedPaths(t *testing.T) watchedPathsBody {
	t.Helper()
	resp := r.do(t, http.MethodGet, watchedPathsRoute, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body watchedPathsBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body
}

var startupItems = rulesapi.WatchedPath{Path: "/Library/StartupItems/", Match: rulesapi.WatchedPathPrefix}

// spec:server-admin-surface/watched-file-paths-are-configured-over-the-api/an-operator-reads-the-watched-path-set
func TestWatchedPathsREST_ReadsTheEmptySetAndWhatIsAlwaysWatched(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})

	body := r.watchedPaths(t)

	assert.Equal(t, int64(0), body.Version)
	assert.Empty(t, body.Paths)
	assert.NotNil(t, body.Paths, "an empty set is an empty list, so a client need not handle null")
	assert.Nil(t, body.UpdatedAt, "nobody has changed the seeded set")
	assert.Equal(t, rulesapi.BuiltInWatchedPaths, body.BuiltIn)
	assert.Equal(t, rulesapi.MaxWatchedPaths, body.MaxPaths)
}

// spec:server-admin-surface/watched-file-paths-are-configured-over-the-api/an-operator-replaces-the-watched-path-set-with-a-reason
func TestWatchedPathsREST_ReplacesTheSetPushesItAndAuditsIt(t *testing.T) {
	t.Parallel()
	hosts := []string{"host-c", "host-a", "host-b"}
	r := newAppControlRig(t, hosts)
	emond := rulesapi.WatchedPath{Path: "/etc/emond.d/rules/", Match: rulesapi.WatchedPathPrefix}

	first := r.do(t, http.MethodPut, watchedPathsRoute,
		map[string]any{"paths": []rulesapi.WatchedPath{startupItems}, "reason": "watch startup items"})
	first.Body.Close()
	require.Equal(t, http.StatusOK, first.StatusCode)

	resp := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{
		"paths":  []rulesapi.WatchedPath{emond, startupItems},
		"reason": "cover the emond rule too",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result replaceWatchedPathsBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, int64(2), result.Set.Version, "each change is the next version")
	assert.Equal(t, []rulesapi.WatchedPath{emond, startupItems}, result.Set.Paths, "order is kept as submitted")
	assert.Equal(t, 3, result.FanoutHosts)
	assert.Zero(t, result.FanoutFailed)

	stored := r.watchedPaths(t)
	assert.Equal(t, int64(2), stored.Version)
	assert.Equal(t, []rulesapi.WatchedPath{emond, startupItems}, stored.Paths)
	require.NotNil(t, stored.UpdatedAt)
	assert.Equal(t, r.actor.Principal.ID, stored.UpdatedBy)

	// Every host gets the second set, carrying its version and its update time as the epoch, in the wire shape the agent and extension
	// decode.
	commands := r.inserter.snapshot()
	require.Len(t, commands, 6, "two changes, three hosts each")
	wantPayload := fmt.Sprintf(`{"version":2,"epoch":%d,"paths":[`+
		`{"path":"/etc/emond.d/rules/","match":"prefix"},{"path":"/Library/StartupItems/","match":"prefix"}]}`,
		stored.UpdatedAt.UnixMicro())
	gotHosts := make([]string, 0, 3)
	for _, c := range commands[3:] {
		assert.Equal(t, rulesapi.CommandTypeSetWatchedPaths, c.Type)
		assert.JSONEq(t, wantPayload, string(c.Payload))
		gotHosts = append(gotHosts, c.HostID)
	}
	assert.ElementsMatch(t, hosts, gotHosts)
	// The epoch moves forward with each change, which is what orders sets on a host once a restore has sent version backwards.
	var firstPayload, secondPayload rulesapi.SetWatchedPathsPayload
	require.NoError(t, json.Unmarshal(commands[0].Payload, &firstPayload))
	require.NoError(t, json.Unmarshal(commands[3].Payload, &secondPayload))
	assert.GreaterOrEqual(t, secondPayload.Epoch, firstPayload.Epoch)
	assert.Positive(t, firstPayload.Epoch)

	events := r.audit.snapshot()
	require.Len(t, events, 2)
	e := events[1]
	assert.Equal(t, identityapi.AuditDetectionConfigWatchedPathsUpdate, e.Action)
	assert.Equal(t, "watched_path_set", e.TargetType)
	assert.Equal(t, "2", e.TargetID)
	assert.Equal(t, r.actor.Principal, e.Actor)
	assert.Equal(t, "cover the emond rule too", e.Payload["reason"])
	assert.EqualValues(t, 1, e.Payload["previous_version"])
	assert.Equal(t, []rulesapi.WatchedPath{startupItems}, e.Payload["previous_paths"])
	assert.Equal(t, []rulesapi.WatchedPath{emond, startupItems}, e.Payload["paths"])
	assert.Equal(t, 3, e.Payload["fanout_hosts"])
	assert.Equal(t, 0, e.Payload["fanout_failed"])
}

// An empty set is how an operator stops watching everything they added; it is stored and pushed like any other.
func TestWatchedPathsREST_ClearsTheSet(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	put := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{"paths": []rulesapi.WatchedPath{startupItems}, "reason": "add"})
	put.Body.Close()

	cleared := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{"paths": []rulesapi.WatchedPath{}, "reason": "no longer needed"})
	cleared.Body.Close()
	require.Equal(t, http.StatusOK, cleared.StatusCode)

	assert.Equal(t, int64(2), r.watchedPaths(t).Version)
	assert.Empty(t, r.watchedPaths(t).Paths)
	commands := r.inserter.snapshot()
	require.Len(t, commands, 2)
	var pushed rulesapi.SetWatchedPathsPayload
	require.NoError(t, json.Unmarshal(commands[1].Payload, &pushed))
	assert.Equal(t, int64(2), pushed.Version)
	assert.Empty(t, pushed.Paths)
	assert.JSONEq(t, `[]`, string(mustField(t, commands[1].Payload, "paths")), "an empty set is sent as an empty list, not null")
}

// spec:server-admin-surface/watched-file-paths-are-configured-over-the-api/a-change-without-a-list-is-refused
// A request without the list is refused rather than read as an empty set, which would remove every path an operator added whenever a
// client misspelled the field.
func TestWatchedPathsREST_RefusesARequestWithoutAList(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	put := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{"paths": []rulesapi.WatchedPath{startupItems}, "reason": "add"})
	put.Body.Close()

	for _, body := range []map[string]any{
		{"reason": "no list"},
		{"path": []rulesapi.WatchedPath{}, "reason": "misspelled field"},
		{"paths": nil, "reason": "null list"},
	} {
		resp := r.do(t, http.MethodPut, watchedPathsRoute, body)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", body)
	}

	stored := r.watchedPaths(t)
	assert.Equal(t, int64(1), stored.Version)
	assert.Equal(t, []rulesapi.WatchedPath{startupItems}, stored.Paths)
	assert.Len(t, r.inserter.snapshot(), 1)
}

// Concurrent replacements are ordered by the row lock: each takes the next version, audits the set it actually replaced, and gets a
// later epoch than the version before it, which is what lets a host order the sets however their commands arrive.
func TestWatchedPathsREST_OrdersConcurrentReplacements(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	const writers = 8

	var wg sync.WaitGroup
	for i := range writers {
		wg.Go(func() {
			path := rulesapi.WatchedPath{Path: fmt.Sprintf("/Library/Watched%d/", i), Match: rulesapi.WatchedPathPrefix}
			resp := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{"paths": []rulesapi.WatchedPath{path}, "reason": "race"})
			resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
	wg.Wait()

	epochs := make(map[int64]int64, writers)
	for _, c := range r.inserter.snapshot() {
		var p rulesapi.SetWatchedPathsPayload
		require.NoError(t, json.Unmarshal(c.Payload, &p))
		epochs[p.Version] = p.Epoch
	}
	require.Len(t, epochs, writers, "every replacement took its own version")
	for v := int64(2); v <= writers; v++ {
		assert.Greater(t, epochs[v], epochs[v-1], "version %d must carry a later epoch than version %d", v, v-1)
	}
	previous := make(map[any]bool, writers)
	for _, e := range r.audit.snapshot() {
		assert.Equal(t, e.Payload["version"].(int64)-1, e.Payload["previous_version"], "each change audits the set it replaced")
		previous[e.Payload["previous_version"]] = true
	}
	assert.Len(t, previous, writers)
}

// The largest set the API accepts, 32 entries at the longest path, fits the request body cap rather than being refused before it is
// validated.
func TestWatchedPathsREST_AcceptsTheLargestValidSet(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	largest := make([]rulesapi.WatchedPath, rulesapi.MaxWatchedPaths)
	for i := range largest {
		prefix := fmt.Sprintf("/Library/Watched/%02d-", i)
		path := prefix + strings.Repeat("a", rulesapi.MaxWatchedPathBytes-len(prefix))
		largest[i] = rulesapi.WatchedPath{Path: path, Match: rulesapi.WatchedPathLiteral}
	}

	resp := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{"paths": largest, "reason": "largest set"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Len(t, r.watchedPaths(t).Paths, rulesapi.MaxWatchedPaths)
}

// spec:server-admin-surface/watched-file-paths-are-configured-over-the-api/a-set-the-server-would-not-watch-is-refused
func TestWatchedPathsREST_RefusesAnInvalidSetWithoutStoringOrPushing(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})

	resp := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{
		"paths":  []rulesapi.WatchedPath{startupItems, {Path: "/Users/", Match: rulesapi.WatchedPathPrefix}},
		"reason": "too broad",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "detection_config.invalid_input", body["error"])
	assert.Contains(t, body["message"], `entry 1 ("/Users/")`)

	assert.Equal(t, int64(0), r.watchedPaths(t).Version)
	assert.Empty(t, r.inserter.snapshot())
	assert.Empty(t, r.audit.snapshot())
}

// spec:server-admin-surface/watched-file-paths-are-configured-over-the-api/a-change-without-a-reason-is-refused
func TestWatchedPathsREST_RefusesAChangeWithoutAReason(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})

	resp := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{"paths": []rulesapi.WatchedPath{startupItems}, "reason": "  "})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	assert.Equal(t, int64(0), r.watchedPaths(t).Version)
	assert.Empty(t, r.inserter.snapshot())
}

// spec:server-admin-surface/watched-file-paths-are-configured-over-the-api/reading-and-changing-the-set-need-their-permissions
func TestWatchedPathsREST_EnforcesReadAndWritePermissions(t *testing.T) {
	t.Parallel()
	t.Run("read", func(t *testing.T) {
		t.Parallel()
		r := newAppControlRig(t, []string{"host-a"}, withAuthZ(denyActionAuthZ{denied: identityapi.ActionDetectionConfigRead}))
		resp := r.do(t, http.MethodGet, watchedPathsRoute, nil)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
	t.Run("write", func(t *testing.T) {
		t.Parallel()
		r := newAppControlRig(t, []string{"host-a"}, withAuthZ(denyActionAuthZ{denied: identityapi.ActionDetectionConfigWrite}))
		resp := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{"paths": []rulesapi.WatchedPath{startupItems}, "reason": "r"})
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Equal(t, int64(0), r.watchedPaths(t).Version)
		assert.Empty(t, r.inserter.snapshot())
	})
}

// The epoch moves forward with the version even when the database clock reads earlier than the last change, as it can after the
// clock is stepped back: a later version with an earlier epoch would let a host reorder the two sets.
func TestWatchedPathsREST_EpochAdvancesPastAClockThatWentBack(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})
	first := r.do(t, http.MethodPut, watchedPathsRoute,
		map[string]any{"paths": []rulesapi.WatchedPath{startupItems}, "reason": "first"})
	first.Body.Close()
	_, err := r.db.ExecContext(t.Context(), `UPDATE watched_path_set SET updated_at = NOW(6) + INTERVAL 1 DAY WHERE id = 1`)
	require.NoError(t, err)
	ahead := r.watchedPaths(t).UpdatedAt

	second := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{"paths": []rulesapi.WatchedPath{}, "reason": "second"})
	second.Body.Close()
	require.Equal(t, http.StatusOK, second.StatusCode)

	stored := r.watchedPaths(t)
	assert.Equal(t, int64(2), stored.Version)
	assert.True(t, stored.UpdatedAt.After(*ahead), "version 2 must carry a later update time than version 1's")
}

// A push that could not even list the hosts is not reported as a push to an empty fleet.
func TestWatchedPathsREST_ReportsAHostListFailure(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"}, func(d *rulesbootstrap.Deps) {
		d.EnrolledHostLister = func(context.Context) ([]string, error) { return nil, errors.New("enrollments unavailable") }
	})

	resp := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{"paths": []rulesapi.WatchedPath{startupItems}, "reason": "r"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, "host_lister_error", result["fanout_skipped_reason"])
	assert.EqualValues(t, 0, result["fanout_hosts"])

	assert.Equal(t, int64(1), r.watchedPaths(t).Version, "the set is stored even though it reached no host")
	events := r.audit.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, "host_lister_error", events[0].Payload["fanout_skipped_reason"])
	assert.Empty(t, r.inserter.snapshot())
}

// The push goes to active enrollments, not to hosts the detection context has seen events from.
func TestWatchedPathsREST_PushesToEnrolledHosts(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"seen-only"}, func(d *rulesbootstrap.Deps) {
		d.EnrolledHostLister = func(context.Context) ([]string, error) { return []string{"enrolled-a", "enrolled-b"}, nil }
	})

	resp := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{"paths": []rulesapi.WatchedPath{startupItems}, "reason": "r"})
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var hosts []string
	for _, c := range r.inserter.snapshot() {
		hosts = append(hosts, c.HostID)
	}
	assert.ElementsMatch(t, []string{"enrolled-a", "enrolled-b"}, hosts)
}

// spec:server-admin-surface/watched-file-paths-are-configured-over-the-api/a-push-that-misses-hosts-does-not-undo-the-change
func TestWatchedPathsREST_KeepsTheChangeWhenThePushFails(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a", "host-b"})
	r.inserter.failBatch(errors.New("synthetic batch insert failure"))

	resp := r.do(t, http.MethodPut, watchedPathsRoute, map[string]any{"paths": []rulesapi.WatchedPath{startupItems}, "reason": "r"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result replaceWatchedPathsBody
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, 2, result.FanoutHosts)
	assert.Equal(t, 2, result.FanoutFailed)

	assert.Equal(t, int64(1), r.watchedPaths(t).Version)
	events := r.audit.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, 2, events[0].Payload["fanout_failed"])
}

// mustField returns one top-level field of a JSON object as raw bytes.
func mustField(t *testing.T, doc []byte, field string) json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc, &fields))
	value, ok := fields[field]
	require.True(t, ok, "field %q missing from %s", field, doc)
	return value
}
