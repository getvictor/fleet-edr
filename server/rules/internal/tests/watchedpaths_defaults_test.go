//go:build integration

package tests

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/watchedpaths"
	"github.com/fleetdm/edr/server/testdb/full"
)

type defaultsRig struct {
	db       *sqlx.DB
	store    *watchedpaths.Store
	svc      *watchedpaths.Service
	inserter *recordingInserter
}

func newDefaultsRig(t *testing.T) *defaultsRig {
	t.Helper()
	db := full.Open(t)
	inserter := newRecordingInserter()
	store := watchedpaths.NewStore(db)
	svc := watchedpaths.NewService(store, inserter.InsertBatch,
		func(context.Context) ([]string, error) { return []string{"host-a", "host-b"}, nil }, nil, slog.Default())
	return &defaultsRig{db: db, store: store, svc: svc, inserter: inserter}
}

func (r *defaultsRig) get(t *testing.T) rulesapi.WatchedPathSet {
	t.Helper()
	set, err := r.store.Get(t.Context())
	require.NoError(t, err)
	return set
}

func pushedPaths(t *testing.T, payload []byte) string {
	t.Helper()
	var p struct {
		Paths json.RawMessage `json:"paths"`
	}
	require.NoError(t, json.Unmarshal(payload, &p))
	return string(p.Paths)
}

// spec:server-admin-surface/the-server-pushes-default-watched-paths/a-deployment-that-never-configured-a-set-pushes-the-defaults
//
// A deployment whose set was never changed is at version 0, and before issue #1167 pushed nothing at all. The shipped file rules
// that depend on the defaults would then never fire anywhere.
func TestWatchedPathDefaults_ANeverConfiguredDeploymentPushesThem(t *testing.T) {
	t.Parallel()
	r := newDefaultsRig(t)
	require.Zero(t, r.get(t).Version)

	require.NoError(t, r.svc.EnsureDefaults(t.Context()))

	set := r.get(t)
	assert.Equal(t, int64(1), set.Version)
	assert.Empty(t, set.Paths, "the operator's set is untouched")
	assert.Equal(t, rulesapi.DefaultWatchedPaths, set.Defaults)
	assert.Equal(t, identityapi.PrincipalSystemID, set.UpdatedBy, "a change by the system, not an operator")
	commands := r.inserter.snapshot()
	require.Len(t, commands, 2, "every enrolled host is sent the set")
	for _, c := range commands {
		assert.JSONEq(t, `[`+defaultsOnTheWire+`]`, pushedPaths(t, c.Payload))
	}
}

// Once the set carries this build's defaults, ensuring them again changes nothing and pushes nothing: it runs on every converge
// pass, so anything else would re-push the set to the whole fleet every few minutes.
func TestWatchedPathDefaults_EnsuringThemAgainIsANoOp(t *testing.T) {
	t.Parallel()
	r := newDefaultsRig(t)
	require.NoError(t, r.svc.EnsureDefaults(t.Context()))
	before := r.get(t)
	pushes := len(r.inserter.snapshot())

	require.NoError(t, r.svc.EnsureDefaults(t.Context()))
	assert.Equal(t, before.Version, r.get(t).Version)
	assert.Len(t, r.inserter.snapshot(), pushes)
}

// spec:server-admin-surface/the-server-pushes-default-watched-paths/a-set-stored-before-the-defaults-keeps-its-paths-and-gains-them
//
// A row written before defaults existed holds a bare array of the operator's paths. It must decode, keep those paths, and be
// brought up to the defaults by a change that moves the version, since a host only applies a set newer than the one it holds.
func TestWatchedPathDefaults_ALegacySetKeepsItsPathsAndGainsThem(t *testing.T) {
	t.Parallel()
	r := newDefaultsRig(t)
	_, err := r.db.Exec(`UPDATE watched_path_set SET version = 4, updated_at = NOW(6), updated_by = 'usr_1',
		paths = JSON_ARRAY(JSON_OBJECT('path', '/etc/periodic/daily/', 'match', 'prefix')) WHERE id = 1`)
	require.NoError(t, err)
	legacy := r.get(t)
	require.Equal(t, []rulesapi.WatchedPath{{Path: "/etc/periodic/daily/", Match: rulesapi.WatchedPathPrefix}}, legacy.Paths)
	require.Empty(t, legacy.Defaults, "a legacy row was pushed with no defaults, and says so")

	require.NoError(t, r.svc.EnsureDefaults(t.Context()))

	set := r.get(t)
	assert.Equal(t, int64(5), set.Version)
	assert.Equal(t, legacy.Paths, set.Paths)
	assert.Equal(t, rulesapi.DefaultWatchedPaths, set.Defaults)
	for _, c := range r.inserter.snapshot() {
		assert.JSONEq(t, `[`+defaultsOnTheWire+`,{"path":"/etc/periodic/daily/","match":"prefix"}]`, pushedPaths(t, c.Payload))
	}
}

// An operator's change is stored with this build's defaults, so it needs no system change after it.
func TestWatchedPathDefaults_AnOperatorChangeCarriesThem(t *testing.T) {
	t.Parallel()
	r := newDefaultsRig(t)
	actor := &identityapi.Actor{Principal: identityapi.UserPrincipal(1, "alice@example.com")}
	_, err := r.svc.Replace(t.Context(), actor, "watch periodic scripts",
		[]rulesapi.WatchedPath{{Path: "/etc/periodic/daily/", Match: rulesapi.WatchedPathPrefix}}, nil)
	require.NoError(t, err)
	assert.Equal(t, rulesapi.DefaultWatchedPaths, r.get(t).Defaults)

	version := r.get(t).Version
	require.NoError(t, r.svc.EnsureDefaults(t.Context()))
	assert.Equal(t, version, r.get(t).Version)
}

// spec:server-admin-surface/the-server-pushes-default-watched-paths/replicas-racing-add-the-defaults-once
//
// Every replica runs the converge loop, so every replica ensures the defaults, and after an upgrade they all find them missing at
// once. One change must win and the rest must see there is nothing left to do, rather than each pushing its own version.
func TestWatchedPathDefaults_ReplicasRacingAddThemOnce(t *testing.T) {
	t.Parallel()
	r := newDefaultsRig(t)
	const replicas = 6
	var wg sync.WaitGroup
	errs := make(chan error, replicas)
	for range replicas {
		wg.Go(func() { errs <- r.svc.EnsureDefaults(t.Context()) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, int64(1), r.get(t).Version, "one change, whichever replica made it")
	assert.Len(t, r.inserter.snapshot(), 2, "one push to each host")
}

// spec:server-admin-surface/hosts-that-miss-the-watched-path-push-get-the-set/a-never-configured-deployment-is-sent-the-defaults
//
// The converge loop is what calls it: a converger wired with EnsureDefaults queues the defaults to a host on a deployment that never
// configured a set, which a converger without it would leave with nothing.
func TestWatchedPathDefaults_TheConvergeLoopEnsuresThem(t *testing.T) {
	t.Parallel()
	r := newDefaultsRig(t)
	history := &fakeCommandHistory{latest: map[string]rulesapi.WatchedPathCommand{}}
	enrolled := []rulesapi.WatchedPathEnrollment{{HostID: "host-a", EnrolledAt: time.Now().Add(-time.Hour)}}
	converger := watchedpaths.NewConverger(r.store, history.insert,
		func(context.Context) ([]rulesapi.WatchedPathEnrollment, error) { return enrolled, nil }, history.list, slog.Default())
	converger.SetEnsureDefaults(r.svc.EnsureDefaults)

	_, err := converger.Converge(t.Context())
	require.NoError(t, err)
	// The fan-out from the system change reached host-a through the service's inserter; the converger itself queued it only if
	// that push is absent from the history it reads, which in this rig it is.
	assert.Equal(t, int64(1), r.get(t).Version)
	assert.Equal(t, []string{"host-a"}, history.takeQueued())
	assert.JSONEq(t, `[`+defaultsOnTheWire+`]`, pushedPaths(t, history.latest["host-a"].Payload))
}

// spec:server-admin-surface/the-server-pushes-default-watched-paths/a-server-from-before-the-defaults-still-reads-the-set
//
// During a rolling upgrade old and new replicas share the database (ADR-0011). A server from before defaults decodes the column
// straight into a list of paths, so what this server writes must still decode that way, or every old replica's watched-path reads,
// writes and converge passes would fail the moment one new replica wrote the set (review on #1179).
func TestWatchedPathDefaults_AServerFromBeforeThemStillReadsTheSet(t *testing.T) {
	t.Parallel()
	r := newDefaultsRig(t)
	actor := &identityapi.Actor{Principal: identityapi.UserPrincipal(1, "alice@example.com")}
	_, err := r.svc.Replace(t.Context(), actor, "watch periodic scripts",
		[]rulesapi.WatchedPath{{Path: "/etc/periodic/daily/", Match: rulesapi.WatchedPathPrefix}}, nil)
	require.NoError(t, err)

	var column []byte
	require.NoError(t, r.db.Get(&column, `SELECT paths FROM watched_path_set WHERE id = 1`))
	var asTheOldServerReadsIt []rulesapi.WatchedPath
	require.NoError(t, json.Unmarshal(column, &asTheOldServerReadsIt), "the old decoder, a plain list of paths")
	assert.Equal(t, append(slices.Clone(rulesapi.DefaultWatchedPaths),
		rulesapi.WatchedPath{Path: "/etc/periodic/daily/", Match: rulesapi.WatchedPathPrefix}), asTheOldServerReadsIt,
		"and it sees the defaults as ordinary entries, which it keeps pushing")
}

// spec:server-admin-surface/the-server-pushes-default-watched-paths/a-set-an-old-server-rewrote-is-restored
//
// An old replica that rewrites the set during the upgrade stores the defaults back as ordinary entries, without the marker. The
// next pass on a new replica must see them as unrecorded, mark them again, and not leave a duplicate of each among the operator's.
func TestWatchedPathDefaults_ASetAnOldServerRewroteIsRestored(t *testing.T) {
	t.Parallel()
	r := newDefaultsRig(t)
	_, err := r.db.Exec(`UPDATE watched_path_set SET version = 7, updated_at = NOW(6), updated_by = 'usr_1', paths = JSON_ARRAY(
		JSON_OBJECT('path', '/etc/emond.d/rules/', 'match', 'prefix'),
		JSON_OBJECT('path', '/private/var/db/emondClients/', 'match', 'prefix'),
		JSON_OBJECT('path', '/Library/StartupItems/', 'match', 'prefix'),
		JSON_OBJECT('path', '/etc/periodic/daily/', 'match', 'prefix')) WHERE id = 1`)
	require.NoError(t, err)
	require.Empty(t, r.get(t).Defaults, "the markers were lost in the old server's write")

	require.NoError(t, r.svc.EnsureDefaults(t.Context()))

	set := r.get(t)
	assert.Equal(t, int64(8), set.Version)
	assert.Equal(t, rulesapi.DefaultWatchedPaths, set.Defaults)
	assert.Equal(t, []rulesapi.WatchedPath{{Path: "/etc/periodic/daily/", Match: rulesapi.WatchedPathPrefix}}, set.Paths,
		"the repeats of the defaults are not left among the operator's paths")
}
