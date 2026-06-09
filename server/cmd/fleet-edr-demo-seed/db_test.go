package main

import (
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
