package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/testdb/full"
	"github.com/fleetdm/edr/test/fakeagent"
)

// insertRole ensures a role row exists so role_bindings' FK is satisfied. INSERT IGNORE because the identity testkit already seeds
// the built-in roles (as the real server does at boot); this just makes the dependency explicit and robust to either state.
func insertRole(t *testing.T, db *sqlx.DB, id string) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`INSERT IGNORE INTO roles (id, display_name, is_builtin) VALUES (?, ?, 1)`, id, id)
	require.NoError(t, err)
}

// insertProcess writes an EXEC-IMAGED process row (exec_time_ns set), which is what waitForProcess gates on: a bare fork row carries
// its parent's path, so the consumers the barrier releases (the app-control block, dns_c2_beacon's suspicion gate) cannot act on it.
// insertForkOnlyProcess covers the pre-exec shape.
func insertProcess(t *testing.T, db *sqlx.DB, hostID string, pid int) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns, exec_time_ns) VALUES (?, ?, 1, '/bin/x', 1, 1)`,
		hostID, pid)
	require.NoError(t, err)
}

// insertForkOnlyProcess writes a row in the pre-exec state the graph builder produces from a fork alone: the path is inherited from
// the parent and exec_time_ns is NULL. waitForProcess must NOT treat this as materialised (issue #661).
func insertForkOnlyProcess(t *testing.T, db *sqlx.DB, hostID string, pid int) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns) VALUES (?, ?, 1, '/bin/parent', 1)`, hostID, pid)
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
	t.Parallel()
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
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()
	s := newSeeder(config{}, db, testHTTPClient(), discardLogger())
	inClause, hostArgs, err := demoHostScope()
	require.NoError(t, err)
	demoHost := firstDemoHostID(t)

	c, err := s.counts(ctx, inClause, hostArgs)
	require.NoError(t, err)
	assert.Equal(t, demoCounts{detectionRuleIDs: map[string]bool{}}, c)

	seeded, err := s.alreadySeeded(ctx)
	require.NoError(t, err)
	assert.False(t, seeded)

	// Rows on a NON-demo host: none of them may satisfy the scoped predicates, even the keychain marker alreadySeeded keys on.
	insertProcess(t, db, "HOST-UNRELATED", 50)
	insertAlert(t, db, "HOST-UNRELATED", keychainRuleID, "detection", "high")

	insertProcess(t, db, demoHost, 100)
	insertAlert(t, db, demoHost, "sudoers_tamper", "detection", "high")
	insertAlert(t, db, demoHost, "demo_blocklist_binary", "application_control", "high")

	c, err = s.counts(ctx, inClause, hostArgs)
	require.NoError(t, err)
	assert.Equal(t, 1, c.processes, "the unrelated host's process is outside the demo scope")
	assert.Equal(t, 1, c.detectionAlerts, "the unrelated host's keychain alert is outside the demo scope")
	assert.Equal(t, 1, c.appControlAlerts)
	assert.Equal(t, map[string]bool{"sudoers_tamper": true}, c.detectionRuleIDs,
		"per-rule fired set feeds verify's per-ExpectRule predicate; scoped to demo hosts")

	seeded, err = s.alreadySeeded(ctx)
	require.NoError(t, err)
	assert.False(t, seeded, "a real deployment's own keychain alert must not read as demo-already-seeded")

	insertAlert(t, db, demoHost, keychainRuleID, "detection", "high")
	seeded, err = s.alreadySeeded(ctx)
	require.NoError(t, err)
	assert.True(t, seeded)
}

func TestWaitForProcess(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()
	s := newSeeder(config{pollInterval: time.Millisecond, verifyTimeout: time.Second}, db, testHTTPClient(), discardLogger())

	insertProcess(t, db, "HOST-B", 200)
	require.NoError(t, s.waitForProcess(ctx, "HOST-B", 200))

	s.cfg.verifyTimeout = 20 * time.Millisecond
	err := s.waitForProcess(ctx, "HOST-B", 999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not met within")

	// A fork-only row must NOT satisfy the barrier: its path is the parent's, so releasing the woven network_connect against it makes
	// dns_c2_beacon's suspicion gate decline the process, and that is a negative match no retry recovers (issue #661).
	insertForkOnlyProcess(t, db, "HOST-B", 300)
	err = s.waitForProcess(ctx, "HOST-B", 300)
	require.Error(t, err, "a pre-exec fork row is not a materialised process for barrier purposes")
	assert.Contains(t, err.Error(), "not met within")

	// Imaging that same pid with the exec releases it.
	_, err = db.ExecContext(ctx,
		`UPDATE processes SET path = '/tmp/.update', exec_time_ns = 2 WHERE host_id = ? AND pid = 300`, "HOST-B")
	require.NoError(t, err)
	s.cfg.verifyTimeout = time.Second
	require.NoError(t, s.waitForProcess(ctx, "HOST-B", 300))
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

// recordingEventsServer serves the seeder's HTTP contract and records the ordered event_type list of each POST /api/events batch, so
// a test can assert postWovenEnvelopes' barrier split (the fork/exec/dns lifecycle batch lands before the network_connect batch).
func recordingEventsServer(t *testing.T) (*httptest.Server, func() [][]string) {
	t.Helper()
	var mu sync.Mutex
	var batches [][]string
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		var envs []struct {
			EventType string `json:"event_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&envs); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		types := make([]string, len(envs))
		for i, e := range envs {
			types[i] = e.EventType
		}
		mu.Lock()
		batches = append(batches, types)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, func() [][]string {
		mu.Lock()
		defer mu.Unlock()
		out := make([][]string, len(batches))
		copy(out, batches)
		return out
	}
}

// beaconEnvelopes builds the dns_c2_beacon-shaped four-event stream (fork, exec, dns_query, network_connect) for one pid: the
// timeline whose same-batch connect-before-exec race postWovenEnvelopes' barrier removes.
func beaconEnvelopes(hostID string) (int, []fakeagent.Envelope) {
	const pid = 7777
	mk := func(eventType, payload string) fakeagent.Envelope {
		return fakeagent.Envelope{EventID: eventType + "-id", HostID: hostID, EventType: eventType, Payload: []byte(payload)}
	}
	return pid, []fakeagent.Envelope{
		mk("fork", `{"child_pid":7777,"parent_pid":1}`),
		mk("exec", `{"pid":7777,"path":"/tmp/.update"}`),
		mk("dns_query", `{"pid":7777,"query_name":"kx7gq2vphj9k3mzw.example.net","response_addresses":["203.0.113.66"]}`),
		mk("network_connect", `{"pid":7777,"direction":"outbound","remote_address":"203.0.113.66"}`),
	}
}

// TestPostWovenEnvelopes_NoConnectSingleBatch pins that an attack with no network_connect (the file-write / exec rules) is posted as
// one unsplit batch, unchanged from before the barrier. No db is touched because the barrier never runs.
func TestPostWovenEnvelopes_NoConnectSingleBatch(t *testing.T) {
	t.Parallel()
	ts, batches := recordingEventsServer(t)
	s := newSeeder(runTestConfig(ts.URL), nil, testHTTPClient(), discardLogger())
	envs := []fakeagent.Envelope{
		{EventType: "fork", Payload: []byte(`{"child_pid":5,"parent_pid":1}`)},
		{EventType: "exec", Payload: []byte(`{"pid":5,"path":"/usr/bin/security"}`)},
		{EventType: "file_event", Payload: []byte(`{"pid":5,"path":"/etc/sudoers"}`)},
	}
	require.NoError(t, s.postWovenEnvelopes(t.Context(), "h", "tok", "sudoers-tamper.yaml", envs))
	got := batches()
	require.Len(t, got, 1, "no network_connect must post a single unsplit batch")
	assert.Equal(t, []string{"fork", "exec", "file_event"}, got[0])
}

// TestPostWovenEnvelopes_FlowBarrier pins the dns_c2_beacon fix (demo-nightly released-leg flake): the connect is released only after
// its process row commits, so the beacon rule never evaluates the connect before the exec materialises and drops the alert past its
// tight flow-process grace.
func TestPostWovenEnvelopes_FlowBarrier(t *testing.T) {
	t.Parallel()
	const hostID = "de300dc2-0000-0000-0000-0000000000aa"

	t.Run("connect posted only after the process materialises", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t)
		pid, envs := beaconEnvelopes(hostID)
		insertProcess(t, db, hostID, pid) // pre-materialise so waitForProcess clears on the first tick
		ts, batches := recordingEventsServer(t)
		s := newSeeder(runTestConfig(ts.URL), db, testHTTPClient(), discardLogger())
		require.NoError(t, s.postWovenEnvelopes(t.Context(), hostID, "tok", "dns-c2-beacon.yaml", envs))
		got := batches()
		require.Len(t, got, 2, "expected a lifecycle batch then a separate connect batch")
		assert.Equal(t, []string{"fork", "exec", "dns_query"}, got[0], "lifecycle batch")
		assert.Equal(t, []string{"network_connect"}, got[1], "connect released after the barrier")
	})

	t.Run("connect withheld when the process never materialises", func(t *testing.T) {
		t.Parallel()
		db := full.Open(t) // no insertProcess: the connecting pid never materialises
		_, envs := beaconEnvelopes(hostID)
		ts, batches := recordingEventsServer(t)
		cfg := runTestConfig(ts.URL)
		cfg.pollInterval = time.Millisecond
		cfg.verifyTimeout = 30 * time.Millisecond
		s := newSeeder(cfg, db, testHTTPClient(), discardLogger())
		err := s.postWovenEnvelopes(t.Context(), hostID, "tok", "dns-c2-beacon.yaml", envs)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "never materialised")
		got := batches()
		require.Len(t, got, 1, "only the lifecycle batch posts; the connect stays withheld")
		assert.NotContains(t, got[0], "network_connect")
	})
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

type hostPID struct {
	hostID string
	pid    int
}

// flowConnectTargets walks the manifest for every woven attack whose scenario emits a network_connect and returns the (captured host
// UUID, offset connecting pid) pairs, replicating the seeder's pid offset. postWovenEnvelopes' flow barrier waits on each of these
// rows before releasing its connect, and the test server runs no processor, so a full-seed test must pre-materialise them (same
// reason as appControlTarget).
func flowConnectTargets(t *testing.T) []hostPID {
	t.Helper()
	var out []hostPID
	for _, h := range hostManifest {
		_, hostID, err := loadHostEnvelopes(h.File)
		require.NoError(t, err)
		for i, atk := range h.Attacks {
			sc, err := loadAttackScenario(atk.File)
			require.NoError(t, err)
			offsetScenarioPIDs(sc, attackPIDOffsetBase+i*attackPIDOffsetStride)
			for _, ev := range sc.Timeline {
				if ev.Type == "network_connect" && ev.PID > 1 {
					out = append(out, hostPID{hostID, ev.PID})
				}
			}
		}
	}
	return out
}

func TestRunSeedsEndToEnd(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()
	insertRole(t, db, "senior_analyst")

	// The app-control attack is woven onto a captured host with an offset pid, so the block event targets
	// (capturedHostID, offsetPid). Replicate the seeder's offset to pre-materialise that process row (the test server does not
	// run the real processor, so weaveAttack's waitForProcess + verify need their rows seeded directly).
	acHost, acPID := appControlTarget(t)
	insertProcess(t, db, acHost, acPID)
	// postWovenEnvelopes' flow barrier waits for each beacon connect's process row before releasing the connect; pre-materialise
	// those too, for the same reason as the app-control row above (the test server runs no processor).
	for _, tgt := range flowConnectTargets(t) {
		insertProcess(t, db, tgt.hostID, tgt.pid)
	}
	// One detection alert per woven attack's expected rule + an app-control alert, on a DEMO host so the scoped verify counts
	// them. The keychain alert is inserted by the loop, so alreadySeeded would normally short-circuit the replay; force runs it
	// anyway.
	for _, rule := range expectedDetectionRules() {
		insertAlert(t, db, acHost, rule, "detection", "high")
	}
	insertAlert(t, db, acHost, "demo_blocklist_binary", "application_control", "high")

	var enrollCalls atomic.Int32
	ts := demoServer(t, &enrollCalls)
	defer ts.Close()

	cfg := runTestConfig(ts.URL)
	cfg.force = true
	s := newSeeder(cfg, db, testHTTPClient(), discardLogger())
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
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()
	s := newSeeder(config{}, db, testHTTPClient(), discardLogger())
	hostID := firstDemoHostID(t) // refresh is scoped to the demo's own host_ids, so seed under a real one.

	// Two processes 30s apart, both stamped ~6 days ago, one still running (NULL exit). last_seen mirrors fork here.
	const sixDaysNs = int64(6*24*60*60) * int64(time.Second)
	staleNewest := time.Now().UnixNano() - sixDaysNs
	staleOlder := staleNewest - int64(30*time.Second)
	_, err := db.ExecContext(ctx,
		`INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns, fork_ingested_at_ns, last_seen_ns, exit_time_ns)
		 VALUES (?, ?, 1, '/bin/older', ?, ?, ?, ?), (?, ?, 1, '/bin/newest', ?, ?, ?, NULL)`,
		hostID, 100, staleOlder, staleOlder, staleOlder, staleOlder+int64(time.Second),
		hostID, 200, staleNewest, staleNewest, staleNewest)
	require.NoError(t, err)
	// Seed the alert ~6 days stale so the test actually exercises the alert shift (a NOW()-stamped alert would pass even if the
	// refresh ignored alerts, and could be shifted into the future undetected).
	insertAlert(t, db, hostID, "sudoers_tamper", "detection", "high")
	_, err = db.ExecContext(ctx,
		`UPDATE alerts SET created_at = DATE_SUB(NOW(), INTERVAL 6 DAY), updated_at = DATE_SUB(NOW(), INTERVAL 6 DAY)
		 WHERE host_id = ?`, hostID)
	require.NoError(t, err)

	require.NoError(t, s.refreshTimestamps(ctx))

	var newestFork, olderFork, lastSeen int64
	var olderExit sql.NullInt64
	var newestExit sql.NullInt64
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT fork_time_ns, last_seen_ns, exit_time_ns FROM processes WHERE host_id = ? AND pid = 200`, hostID).
		Scan(&newestFork, &lastSeen, &newestExit))
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT fork_time_ns, exit_time_ns FROM processes WHERE host_id = ? AND pid = 100`, hostID).Scan(&olderFork, &olderExit))

	// Newest fork now lands ~recentTailOffset before now (allow a generous slop for test wall-clock drift).
	wantNewest := time.Now().Add(-recentTailOffset).UnixNano()
	assert.InDelta(t, wantNewest, newestFork, float64(2*time.Minute), "newest fork slid to ~now-offset")
	assert.Equal(t, newestFork, lastSeen, "last_seen slid by the same delta as fork")
	assert.False(t, newestExit.Valid, "running process keeps NULL exit after the shift")
	// Relative spacing is preserved: the older fork stays 30s behind the newest.
	assert.Equal(t, int64(30*time.Second), newestFork-olderFork, "30s gap preserved")
	require.True(t, olderExit.Valid)
	assert.Equal(t, olderFork+int64(time.Second), olderExit.Int64, "exited process keeps its 1s lifetime")

	// The alert's created_at slid into the recent past: recent AND not future-dated (a future created_at yields a negative
	// TIMESTAMPDIFF, which the upper-bound check alone would not catch).
	var alertAgeSec int64
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT TIMESTAMPDIFF(SECOND, created_at, NOW()) FROM alerts WHERE host_id = ?`, hostID).Scan(&alertAgeSec))
	assert.GreaterOrEqual(t, alertAgeSec, int64(0), "alert fired-at must not be in the future")
	assert.Less(t, alertAgeSec, int64(10*time.Minute/time.Second), "alert fired-at is recent after refresh")
}

// TestRefreshTimestampsIgnoresSynthesizedExit is the regression for the empty-1h-window bug: the process-TTL reconciler
// force-exits stale processes at fork + maxAge, so a long-stale demo carries an exit_time_ns ~maxAge PAST the real device tail.
// The anchor must ignore the exit columns (else the delta shrinks by maxAge and every fork stays stale), and the synthesized exit
// must be cleared so the refreshed process reads as still-running rather than landing a future-dated exit.
func TestRefreshTimestampsIgnoresSynthesizedExit(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()
	s := newSeeder(config{}, db, testHTTPClient(), discardLogger())
	hostID := firstDemoHostID(t)

	// Fork ~6h stale; the TTL reconciler synthesized an exit at fork + 6h maxAge (past the device tail). A second, genuinely
	// exited process keeps its real (small-lifetime) captured exit.
	const sixHoursNs = int64(6*60*60) * int64(time.Second)
	staleFork := time.Now().UnixNano() - sixHoursNs
	_, err := db.ExecContext(ctx,
		`INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns, exec_time_ns, exit_time_ns, exit_reason)
		 VALUES (?, ?, 1, '/bin/ttl', ?, ?, ?, ?), (?, ?, 1, '/bin/real', ?, ?, ?, 'exited')`,
		hostID, 300, staleFork, staleFork, staleFork+sixHoursNs, "ttl_reconciliation",
		hostID, 400, staleFork, staleFork, staleFork+int64(2*time.Second))
	require.NoError(t, err)

	require.NoError(t, s.refreshTimestamps(ctx))

	var ttlFork int64
	var ttlExit, ttlReason sql.NullString
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT fork_time_ns, exit_time_ns, exit_reason FROM processes WHERE host_id=? AND pid=300`, hostID).
		Scan(&ttlFork, &ttlExit, &ttlReason))
	// Anchor ignored the synthesized exit, so the fork slid all the way to ~now-offset (within the 1h window), not 6h stale.
	wantFork := time.Now().Add(-recentTailOffset).UnixNano()
	assert.InDelta(t, wantFork, ttlFork, float64(2*time.Minute), "fork slid recent despite the future-dated TTL exit")
	assert.False(t, ttlExit.Valid, "synthesized TTL exit cleared to NULL (process reads as still-running)")
	assert.False(t, ttlReason.Valid, "synthesized TTL exit_reason cleared")

	// The genuinely-exited process keeps a real exit that slid into the recent past with its fork.
	var realFork, realExit int64
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT fork_time_ns, exit_time_ns FROM processes WHERE host_id=? AND pid=400`, hostID).Scan(&realFork, &realExit))
	assert.Equal(t, realFork+int64(2*time.Second), realExit, "real captured exit kept its 2s lifetime")
	assert.Less(t, realExit, time.Now().UnixNano(), "real exit stayed in the past")
}

// TestRefreshTimestampsNoRows is a no-op when no replayed event/process rows exist (an alert alone must not trigger a shift). The
// before/after compare pins the no-op: the assertion would catch a refresh that shifted alert-only data.
func TestRefreshTimestampsNoRows(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()
	s := newSeeder(config{}, db, testHTTPClient(), discardLogger())
	hostID := firstDemoHostID(t)
	insertAlert(t, db, hostID, "sudoers_tamper", "detection", "high")

	var before time.Time
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT created_at FROM alerts WHERE host_id = ?`, hostID).Scan(&before))

	require.NoError(t, s.refreshTimestamps(ctx))

	var after time.Time
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT created_at FROM alerts WHERE host_id = ?`, hostID).Scan(&after))
	assert.Equal(t, before, after, "alert-only data must not be shifted when no replayed rows exist")
}

// firstDemoHostID returns a captured demo host UUID, the scope refreshTimestamps applies its shift to.
func firstDemoHostID(t *testing.T) string {
	t.Helper()
	ids, err := demoHostIDs()
	require.NoError(t, err)
	require.NotEmpty(t, ids)
	return ids[0]
}

func TestRunSkipsWhenAlreadySeeded(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()
	insertRole(t, db, "senior_analyst")
	// The marker alert must sit on a DEMO host: alreadySeeded is scoped to the demo's own host UUIDs so a real deployment's
	// keychain alert can't read as demo data.
	insertAlert(t, db, firstDemoHostID(t), keychainRuleID, "detection", "high")

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

// TestVerifyReportsMissingRule exercises the tightened per-rule predicate's failure path (the exact shape of the 2026-07-02
// nightly loss): every expected rule except one has fired, and verify must time out with an error that NAMES the missing rule
// instead of passing on "any detection alert".
func TestVerifyReportsMissingRule(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()
	s := newSeeder(config{pollInterval: time.Millisecond, verifyTimeout: 30 * time.Millisecond}, db, testHTTPClient(), discardLogger())

	demoHost := firstDemoHostID(t)

	expected := expectedDetectionRules()
	require.Greater(t, len(expected), 1, "the manifest weaves more than one detection rule")
	withheld := expected[0]

	insertProcess(t, db, demoHost, 100)
	insertAlert(t, db, demoHost, "demo_blocklist_binary", "application_control", "high")
	for _, rule := range expected[1:] {
		insertAlert(t, db, demoHost, rule, "detection", "high")
	}

	err := s.verify(ctx)
	require.Error(t, err, "verify must fail when one expected rule never fired")
	assert.Contains(t, err.Error(), withheld, "the timeout error names the missing rule")
}
