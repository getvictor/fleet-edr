package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb/full"
)

// insertRole ensures a role row exists so role_bindings' FK is satisfied. INSERT IGNORE because the identity testkit already seeds
// the built-in roles (as the real server does at boot); this just makes the dependency explicit and robust to either state.
func insertRole(t *testing.T, db *sqlx.DB, id string) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`INSERT IGNORE INTO roles (id, display_name, is_builtin) VALUES (?, ?, 1)`, id, id)
	require.NoError(t, err)
}

func insertProcess(t *testing.T, db *sqlx.DB, hostID string, pid int) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns) VALUES (?, ?, 1, '/bin/x', 1)`, hostID, pid)
	require.NoError(t, err)
}

func insertAlert(t *testing.T, db *sqlx.DB, hostID, ruleID, source, severity string) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO alerts (host_id, rule_id, source, severity, title, description) VALUES (?, ?, ?, ?, ?, '')`,
		hostID, ruleID, source, severity, ruleID)
	require.NoError(t, err)
}

func TestSeedDemoUser(t *testing.T) {
	db := full.Open(t)
	ctx := t.Context()
	insertRole(t, db, "senior_analyst")

	const email, subject = "demo@fleet-edr.local", "ChdkZW1vCgVsb2NhbA"
	require.NoError(t, seedDemoUser(ctx, db, email, subject, "senior_analyst"))

	var userID int64
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ?`, email).Scan(&userID))

	var identityCount, bindingCount int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM identities WHERE provider = 'oidc' AND subject = ? AND user_id = ?`, subject, userID).Scan(&identityCount))
	assert.Equal(t, 1, identityCount)
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM role_bindings WHERE user_id = ? AND role_id = 'senior_analyst'`, userID).Scan(&bindingCount))
	assert.Equal(t, 1, bindingCount)

	// Idempotent: a second run must not duplicate any row.
	require.NoError(t, seedDemoUser(ctx, db, email, subject, "senior_analyst"))
	var users, identities, bindings int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE email = ?`, email).Scan(&users))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identities WHERE subject = ?`, subject).Scan(&identities))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM role_bindings WHERE user_id = ?`, userID).Scan(&bindings))
	assert.Equal(t, 1, users)
	assert.Equal(t, 1, identities)
	assert.Equal(t, 1, bindings)
}

func TestCountsAndAlreadySeeded(t *testing.T) {
	db := full.Open(t)
	ctx := t.Context()
	s := newSeeder(config{}, db, testHTTPClient(), discardLogger())

	c, err := s.counts(ctx)
	require.NoError(t, err)
	assert.Equal(t, demoCounts{}, c)

	seeded, err := s.alreadySeeded(ctx)
	require.NoError(t, err)
	assert.False(t, seeded)

	insertProcess(t, db, "HOST-A", 100)
	insertAlert(t, db, "HOST-A", "sudoers_tamper", "detection", "high")
	insertAlert(t, db, "HOST-A", "demo_blocklist_binary", "application_control", "high")
	insertAlert(t, db, "HOST-A", keychainRuleID, "detection", "high")

	c, err = s.counts(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, c.processes)
	assert.Equal(t, 2, c.detectionAlerts)
	assert.Equal(t, 1, c.appControlAlerts)

	seeded, err = s.alreadySeeded(ctx)
	require.NoError(t, err)
	assert.True(t, seeded)
}

func TestWaitForProcess(t *testing.T) {
	db := full.Open(t)
	ctx := t.Context()
	s := newSeeder(config{pollInterval: time.Millisecond, verifyTimeout: time.Second}, db, testHTTPClient(), discardLogger())

	insertProcess(t, db, "HOST-B", 200)
	require.NoError(t, s.waitForProcess(ctx, "HOST-B", 200))

	s.cfg.verifyTimeout = 20 * time.Millisecond
	err := s.waitForProcess(ctx, "HOST-B", 999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not met within")
}

// demoServer stands in for the EDR ingest API: readiness, enroll (echoing the requested host id), and events.
func demoServer(t *testing.T, enrollCalls *atomic.Int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/api/enroll", func(w http.ResponseWriter, r *http.Request) {
		enrollCalls.Add(1)
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = json.NewEncoder(w).Encode(map[string]any{"host_id": req["hardware_uuid"], "host_token": "tok"})
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return httptest.NewServer(mux)
}

func runTestConfig(serverURL string) config {
	return config{
		serverURL:       serverURL,
		enrollSecret:    "test-secret",
		pollInterval:    time.Millisecond,
		readyTimeout:    2 * time.Second,
		verifyTimeout:   2 * time.Second,
		demoEmail:       "demo@fleet-edr.local",
		demoOIDCSubject: "ChdkZW1v",
		demoRole:        "senior_analyst",
	}
}

// appControlTarget finds the app-control attack in the host manifest and returns the (captured host UUID, offset pid) the
// fabricated block event will target, replicating the seeder's pid offset so a test can pre-materialise that process row.
func appControlTarget(t *testing.T) (string, int) {
	t.Helper()
	for _, h := range hostManifest {
		for i, atk := range h.Attacks {
			if atk.Kind != kindAppControl {
				continue
			}
			_, hostID, err := loadHostEnvelopes(h.File)
			require.NoError(t, err)
			sc, err := loadAttackScenario(atk.File)
			require.NoError(t, err)
			offsetScenarioPIDs(sc, attackPIDOffsetBase+i*attackPIDOffsetStride)
			pid, _, ok := firstExec(sc)
			require.True(t, ok, "app-control scenario %s has an exec", atk.File)
			return hostID, pid
		}
	}
	t.Fatal("no app-control attack in hostManifest")
	return "", 0
}

func TestRunSeedsEndToEnd(t *testing.T) {
	db := full.Open(t)
	ctx := t.Context()
	insertRole(t, db, "senior_analyst")

	// The app-control attack is woven onto a captured host with an offset pid, so the block event targets
	// (capturedHostID, offsetPid). Replicate the seeder's offset to pre-materialise that process row (the test server does not
	// run the real processor, so weaveAttack's waitForProcess + verify need their rows seeded directly).
	acHost, acPID := appControlTarget(t)
	insertProcess(t, db, acHost, acPID)
	// A detection + an app-control alert so verify's predicate is satisfied. No keychain alert, so alreadySeeded stays false and
	// the full replay path runs.
	insertAlert(t, db, "HOST-SEED", "sudoers_tamper", "detection", "high")
	insertAlert(t, db, acHost, "demo_blocklist_binary", "application_control", "high")

	var enrollCalls atomic.Int32
	ts := demoServer(t, &enrollCalls)
	defer ts.Close()

	s := newSeeder(runTestConfig(ts.URL), db, testHTTPClient(), discardLogger())
	require.NoError(t, s.run(ctx))

	assert.Equal(t, len(hostManifest), int(enrollCalls.Load()),
		"every rich captured host was enrolled exactly once (woven attacks reuse the host token)")

	var userCount int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE email = 'demo@fleet-edr.local'`).Scan(&userCount))
	assert.Equal(t, 1, userCount, "SSO demo user provisioned")
}

// TestRefreshTimestamps confirms the already-seeded restart path slides every replayed timestamp forward by one delta: the newest
// process row lands ~recentTailOffset before now, relative offsets are preserved, NULL exit columns stay NULL, and the alert
// "fired at" slides with the events so the UI's alert -> tree pivot keeps working.
func TestRefreshTimestamps(t *testing.T) {
	db := full.Open(t)
	ctx := t.Context()
	s := newSeeder(config{}, db, testHTTPClient(), discardLogger())

	// Two processes 30s apart, both stamped ~6 days ago, one still running (NULL exit). last_seen mirrors fork here.
	const sixDaysNs = int64(6*24*60*60) * int64(time.Second)
	staleNewest := time.Now().UnixNano() - sixDaysNs
	staleOlder := staleNewest - int64(30*time.Second)
	_, err := db.ExecContext(ctx,
		`INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns, fork_ingested_at_ns, last_seen_ns, exit_time_ns)
		 VALUES (?, ?, 1, '/bin/older', ?, ?, ?, ?), (?, ?, 1, '/bin/newest', ?, ?, ?, NULL)`,
		"HOST-R", 100, staleOlder, staleOlder, staleOlder, staleOlder+int64(time.Second),
		"HOST-R", 200, staleNewest, staleNewest, staleNewest)
	require.NoError(t, err)
	insertAlert(t, db, "HOST-R", "sudoers_tamper", "detection", "high")

	require.NoError(t, s.refreshTimestamps(ctx))

	var newestFork, olderFork, lastSeen int64
	var olderExit sql.NullInt64
	var newestExit sql.NullInt64
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT fork_time_ns, last_seen_ns, exit_time_ns FROM processes WHERE host_id = 'HOST-R' AND pid = 200`).
		Scan(&newestFork, &lastSeen, &newestExit))
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT fork_time_ns, exit_time_ns FROM processes WHERE host_id = 'HOST-R' AND pid = 100`).Scan(&olderFork, &olderExit))

	// Newest fork now lands ~recentTailOffset before now (allow a generous slop for test wall-clock drift).
	wantNewest := time.Now().Add(-recentTailOffset).UnixNano()
	assert.InDelta(t, wantNewest, newestFork, float64(2*time.Minute), "newest fork slid to ~now-offset")
	assert.Equal(t, newestFork, lastSeen, "last_seen slid by the same delta as fork")
	assert.False(t, newestExit.Valid, "running process keeps NULL exit after the shift")
	// Relative spacing is preserved: the older fork stays 30s behind the newest.
	assert.Equal(t, int64(30*time.Second), newestFork-olderFork, "30s gap preserved")
	require.True(t, olderExit.Valid)
	assert.Equal(t, olderFork+int64(time.Second), olderExit.Int64, "exited process keeps its 1s lifetime")

	// The alert's created_at slid into the recent past (was ~6 days stale).
	var alertAgeSec int64
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT TIMESTAMPDIFF(SECOND, created_at, NOW()) FROM alerts WHERE host_id = 'HOST-R'`).Scan(&alertAgeSec))
	assert.Less(t, alertAgeSec, int64(10*time.Minute/time.Second), "alert fired-at is recent after refresh")
}

// TestRefreshTimestampsIgnoresSynthesizedExit is the regression for the empty-1h-window bug: the process-TTL reconciler
// force-exits stale processes at fork + maxAge, so a long-stale demo carries an exit_time_ns ~maxAge PAST the real device tail.
// The anchor must ignore the exit columns (else the delta shrinks by maxAge and every fork stays stale), and the synthesized exit
// must be cleared so the refreshed process reads as still-running rather than landing a future-dated exit.
func TestRefreshTimestampsIgnoresSynthesizedExit(t *testing.T) {
	db := full.Open(t)
	ctx := t.Context()
	s := newSeeder(config{}, db, testHTTPClient(), discardLogger())

	// Fork ~6h stale; the TTL reconciler synthesized an exit at fork + 6h maxAge (past the device tail). A second, genuinely
	// exited process keeps its real (small-lifetime) captured exit.
	const sixHoursNs = int64(6*60*60) * int64(time.Second)
	staleFork := time.Now().UnixNano() - sixHoursNs
	_, err := db.ExecContext(ctx,
		`INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns, exec_time_ns, exit_time_ns, exit_reason)
		 VALUES (?, ?, 1, '/bin/ttl', ?, ?, ?, ?), (?, ?, 1, '/bin/real', ?, ?, ?, 'exited')`,
		"HOST-T", 300, staleFork, staleFork, staleFork+sixHoursNs, "ttl_reconciliation",
		"HOST-T", 400, staleFork, staleFork, staleFork+int64(2*time.Second))
	require.NoError(t, err)

	require.NoError(t, s.refreshTimestamps(ctx))

	var ttlFork int64
	var ttlExit, ttlReason sql.NullString
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT fork_time_ns, exit_time_ns, exit_reason FROM processes WHERE host_id='HOST-T' AND pid=300`).
		Scan(&ttlFork, &ttlExit, &ttlReason))
	// Anchor ignored the synthesized exit, so the fork slid all the way to ~now-offset (within the 1h window), not 6h stale.
	wantFork := time.Now().Add(-recentTailOffset).UnixNano()
	assert.InDelta(t, wantFork, ttlFork, float64(2*time.Minute), "fork slid recent despite the future-dated TTL exit")
	assert.False(t, ttlExit.Valid, "synthesized TTL exit cleared to NULL (process reads as still-running)")
	assert.False(t, ttlReason.Valid, "synthesized TTL exit_reason cleared")

	// The genuinely-exited process keeps a real exit that slid into the recent past with its fork.
	var realFork, realExit int64
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT fork_time_ns, exit_time_ns FROM processes WHERE host_id='HOST-T' AND pid=400`).Scan(&realFork, &realExit))
	assert.Equal(t, realFork+int64(2*time.Second), realExit, "real captured exit kept its 2s lifetime")
	assert.Less(t, realExit, time.Now().UnixNano(), "real exit stayed in the past")
}

// TestRefreshTimestampsNoRows is a no-op when no replayed event/process rows exist (an alert alone must not trigger a shift).
func TestRefreshTimestampsNoRows(t *testing.T) {
	db := full.Open(t)
	ctx := t.Context()
	s := newSeeder(config{}, db, testHTTPClient(), discardLogger())
	insertAlert(t, db, "HOST-EMPTY", "sudoers_tamper", "detection", "high")
	require.NoError(t, s.refreshTimestamps(ctx))
}

func TestRunSkipsWhenAlreadySeeded(t *testing.T) {
	db := full.Open(t)
	ctx := t.Context()
	insertRole(t, db, "senior_analyst")
	insertAlert(t, db, "HOST-OLD", keychainRuleID, "detection", "high")

	var enrollCalls atomic.Int32
	ts := demoServer(t, &enrollCalls)
	defer ts.Close()

	s := newSeeder(runTestConfig(ts.URL), db, testHTTPClient(), discardLogger())
	require.NoError(t, s.run(ctx))

	assert.Equal(t, 0, int(enrollCalls.Load()), "replay skipped when demo data already present")

	// The demo-user seed still runs on the already-seeded path.
	var userCount int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE email = 'demo@fleet-edr.local'`).Scan(&userCount))
	assert.Equal(t, 1, userCount)
}
