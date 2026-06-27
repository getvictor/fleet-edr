//go:build integration

package integration

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/coordination/leader"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/migrations/runner"
	responsemigrations "github.com/fleetdm/edr/server/response/migrations"
	"github.com/fleetdm/edr/server/testdb/full"
)

// TestMultiReplicaProcessorClaimsDisjointBatches proves the SKIP LOCKED batch-claiming the detection processor relies on hands two
// concurrent replicas disjoint event sets, which is what lets the processor scale across replicas (it is deliberately NOT
// leader-gated; see the periodic-tasks requirement for the tasks that are).
func TestMultiReplicaProcessorClaimsDisjointBatches(t *testing.T) {
	t.Run("spec:server-availability/the-processor-scales-across-replicas-via-skip-locked/two-replicas-claim-disjoint-event-batches", func(t *testing.T) {
		db := full.Open(t)
		const (
			batch = 50
			total = 4 * batch // headroom so both replicas can claim a full batch and rows are left over
		)
		seedUnprocessedEvents(t, db, total)

		// Release both claims together so their SELECT ... FOR UPDATE SKIP LOCKED statements overlap and genuinely exercise the
		// skip path, rather than serialising (which would also be disjoint but would not test SKIP LOCKED).
		start := make(chan struct{})
		claim := func() []string {
			<-start
			ids, err := claimBatchSkipLocked(t.Context(), db, batch)
			require.NoError(t, err)
			return ids
		}

		var replicaA, replicaB []string
		var wg sync.WaitGroup
		wg.Go(func() { replicaA = claim() })
		wg.Go(func() { replicaB = claim() })
		close(start)
		wg.Wait()

		require.Len(t, replicaA, batch, "replica A should claim a full batch")
		require.Len(t, replicaB, batch, "replica B should claim a full batch")

		// The property that makes the processor safe to run on every replica: no event is claimed by both.
		seen := make(map[string]struct{}, len(replicaA))
		for _, id := range replicaA {
			seen[id] = struct{}{}
		}
		for _, id := range replicaB {
			_, dup := seen[id]
			require.Falsef(t, dup, "event %s claimed by both replicas; SKIP LOCKED must hand out disjoint batches", id)
		}
	})
}

// TestMultiReplicaSessionsAndCSRFValidateAcrossReplicas proves a session (and its CSRF token) minted against the shared MySQL
// store validates on a different replica with no shared in-process state. Two stacks share one database; requests target replica B
// while the session is seeded as replica A's login would have written it.
func TestMultiReplicaSessionsAndCSRFValidateAcrossReplicas(t *testing.T) {
	db := full.Open(t)
	_ = setupReplica(t, db) // replica A: where the session is conceptually minted (seeded into the shared store below)
	replicaB := setupReplica(t, db)

	// spec:server-availability/the-server-holds-no-in-process-state-that-survives-a-request-lifetime/state-written-on-one-replica-is-served-by-another
	t.Run("spec:server-availability/sessions-and-csrf-tokens-validate-across-any-replica/session-minted-on-replica-a-validates-on-replica-b", func(t *testing.T) {
		// A session row in the shared store stands for one replica A minted at login. Replica B, a distinct stack with no in-process
		// session state, must validate it purely from the store.
		user := testkit.SeedJITUser(t, db, "xrep-session@multi.test", "auditor")

		resp, err := http.DefaultClient.Do(newGet(t, replicaB.Server.URL+"/api/audit-events", user))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "replica B must validate a session minted against the shared store")

		// Control: with no cookie replica B rejects, proving the 200 above came from validating the seeded session, not an open route.
		anonReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, replicaB.Server.URL+"/api/audit-events", nil)
		require.NoError(t, err)
		anon, err := http.DefaultClient.Do(anonReq)
		require.NoError(t, err)
		defer anon.Body.Close()
		require.Equal(t, http.StatusUnauthorized, anon.StatusCode, "replica B must reject an anonymous request")
	})

	t.Run("spec:server-availability/sessions-and-csrf-tokens-validate-across-any-replica/csrf-token-from-replica-a-passes-on-replica-b", func(t *testing.T) {
		// senior_analyst clears the authz + freshness gates on the unsafe isolate command, so a 403 here can only be the CSRF
		// middleware rejecting the token, which is exactly what we are pinning does NOT happen cross-replica.
		user := testkit.SeedJITUser(t, db, "xrep-csrf@multi.test", "senior_analyst")

		resp := postCommand(t, replicaB, user, isolateBody("host-xrep"))
		defer resp.Body.Close()
		require.NotEqual(t, http.StatusForbidden, resp.StatusCode,
			"replica B must accept the CSRF token minted against the shared store")

		// Control: the same unsafe request without the CSRF header is rejected, proving the token (not an unguarded POST) is what
		// passed the middleware above.
		noTokenReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			replicaB.Server.URL+"/api/commands", strings.NewReader(isolateBody("host-xrep")))
		require.NoError(t, err)
		noTokenReq.Header.Set("Content-Type", "application/json")
		noTokenReq.AddCookie(&http.Cookie{Name: identityapi.SessionCookieName, Value: user.SessionCookie})
		noToken, err := http.DefaultClient.Do(noTokenReq)
		require.NoError(t, err)
		defer noToken.Body.Close()
		require.Equal(t, http.StatusForbidden, noToken.StatusCode, "replica B must reject an unsafe request carrying no CSRF token")
	})
}

// TestMultiReplicaMigrationsSafeUnderRollingUpgrade proves the boot-time migration advisory lock serializes concurrent applies, so
// several replicas booting at once during a rolling upgrade never run goose Up against the same database simultaneously. The
// database already carries the response corpus (full.Open applied it), so each apply below is the no-op re-apply a second replica
// performs; it must stay safe under concurrency.
func TestMultiReplicaMigrationsSafeUnderRollingUpgrade(t *testing.T) {
	t.Run("spec:server-availability/schema-migrations-are-safe-under-rolling-upgrade/goose-tracking-table-lock-prevents-concurrent-apply", func(t *testing.T) {
		db := full.Open(t)
		const replicas = 5
		// Each simulated replica holds a pooled connection while it blocks on GET_LOCK, and the lock-holder needs another for the
		// goose apply. In production each replica process has its own pool and takes the lock once; modelling several in one pool
		// needs headroom above the small per-test default or the pool deadlocks (every connection parked on a GET_LOCK wait).
		db.SetMaxOpenConns(replicas + 5)
		coord := leader.NewMySQL(db, slog.Default())
		lockName := "edr_test_migrations_" + randomHex(t)

		var inCritical, maxConcurrent, applied atomic.Int64
		var wg sync.WaitGroup
		for range replicas {
			wg.Go(func() {
				// require would call FailNow from a non-test goroutine (illegal), so assert is correct here.
				assert.NoError(t, coord.WithLock(t.Context(), lockName, func(ctx context.Context) error {
					if err := applyResponseSchemaTrackingConcurrency(ctx, db, &inCritical, &maxConcurrent); err != nil {
						return err
					}
					applied.Add(1)
					return nil
				}))
			})
		}
		wg.Wait()

		assert.Equal(t, int64(1), maxConcurrent.Load(),
			"the advisory lock must serialize boot-time applies: never two goose Up runs at once")
		assert.EqualValues(t, replicas, applied.Load(),
			"every replica applies (goose makes the re-apply a no-op) and boots successfully")
	})
}

// applyResponseSchemaTrackingConcurrency runs the response goose apply (a no-op re-apply, since full.Open already applied it) while
// recording how many callers are inside the critical section at once. A working advisory lock keeps maxConcurrent at 1. Extracted
// from the test body so the test function stays under the cognitive-complexity limit.
func applyResponseSchemaTrackingConcurrency(ctx context.Context, db *sqlx.DB, inCritical, maxConcurrent *atomic.Int64) error {
	cur := inCritical.Add(1)
	defer inCritical.Add(-1)
	recordMax(maxConcurrent, cur)
	time.Sleep(20 * time.Millisecond) // widen the apply window so a broken lock would overlap and bump the high-water mark
	return runner.Up(ctx, db, responsemigrations.FS, runner.Options{
		Context:   "response",
		TableName: "response_goose_db_version",
	})
}

// recordMax lifts maxConcurrent to cur if cur is larger, retrying the CAS until it wins (the value only ever rises here, so a lost
// race means another goroutine already set an equal-or-higher mark).
func recordMax(maxConcurrent *atomic.Int64, cur int64) {
	for {
		m := maxConcurrent.Load()
		if cur <= m || maxConcurrent.CompareAndSwap(m, cur) {
			return
		}
	}
}

// seedUnprocessedEvents inserts n events in the unprocessed state (processed = 0) into the visibility event_queue for the SKIP LOCKED
// claim test (ADR-0015: the processor claims from the queue, not the dropped events table). All share one host so the per-host ordering
// (host_id, timestamp_ns) is well-defined and the two batches are contiguous ranges.
func seedUnprocessedEvents(t *testing.T, db *sqlx.DB, n int) {
	t.Helper()
	ctx := t.Context()
	const hostID = "host-skiplocked"
	for i := range n {
		_, err := db.ExecContext(ctx,
			`INSERT INTO event_queue (event_id, host_id, timestamp_ns, ingested_at_ns, event_type, payload)
			 VALUES (?, ?, ?, ?, 'process_exec', JSON_OBJECT('pid', ?))`,
			fmt.Sprintf("evt-%05d", i), hostID, int64(i+1), int64(i+1), i+1)
		require.NoErrorf(t, err, "seed event %d", i)
	}
}

// claimBatchSkipLocked mirrors the visibility EventLog's Claim verbatim: claim up to limit unprocessed events from event_queue with
// SELECT ... FOR UPDATE SKIP LOCKED, then transition them to processed = 2 in the same transaction. The internal eventlog store is
// unreachable from this cross-context package (Go's internal/ rule), so the claim is reproduced here on a dedicated connection (one
// replica's session) to assert two concurrent claimers get disjoint rows.
func claimBatchSkipLocked(ctx context.Context, db *sqlx.DB, limit int) ([]string, error) {
	conn, err := db.Connx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }() // rollback after commit is a no-op

	var ids []string
	if err := tx.SelectContext(ctx, &ids, `
		SELECT event_id FROM event_queue
		WHERE processed = 0
		ORDER BY host_id, timestamp_ns
		LIMIT ?
		FOR UPDATE SKIP LOCKED`, limit); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return ids, tx.Commit()
	}

	// Hold the row locks briefly so the sibling claimer's SELECT overlaps and must skip these rows rather than serialise behind us.
	time.Sleep(40 * time.Millisecond)

	q, args, err := sqlx.In("UPDATE event_queue SET processed = 2 WHERE event_id IN (?)", ids)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return nil, err
	}
	return ids, tx.Commit()
}

// randomHex returns 8 random hex chars to make per-run advisory lock names unique, so this test never clashes with a parallel
// package sharing the same MySQL server (GET_LOCK names are server-global) or with the production names.
func randomHex(t *testing.T) string {
	t.Helper()
	var b [4]byte
	_, err := crand.Read(b[:])
	require.NoError(t, err)
	return hex.EncodeToString(b[:])
}
