package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/test/fakeagent"
)

// Constants for the synthetic application-control block. The block decision is normally made on-device by the extension's AUTH_EXEC
// walker; the demo fabricates one so the unified alerts view shows an application_control source alongside detection alerts.
const (
	appControlEventType = "application_control_block"
	appControlRuleID    = "demo_blocklist_binary"
	appControlRuleType  = "BINARY"
	appControlSeverity  = "high"
	appControlMessage   = "Blocked by Acme Corp application-control policy."

	// keychainRuleID is the marker the already-seeded check looks for: if a credential_keychain_dump alert exists, the demo data
	// is present and replay is skipped (unless --force).
	keychainRuleID = "credential_keychain_dump"
)

const (
	// httpClientTimeout bounds every enroll, ingest, and readiness request.
	httpClientTimeout = 30 * time.Second
	// errorBodyLimit caps how much of a failed response body is read into an error message.
	errorBodyLimit = 1024
	// maxResponseBytes caps a decoded success response so a malformed or oversized body cannot exhaust memory.
	maxResponseBytes = 1 << 20
)

// seeder drives the demo seed end to end: wait for readiness, replay the curated corpus, fabricate the app-control block, verify the
// processor materialised everything, and optionally provision the SSO demo user.
type seeder struct {
	cfg config
	db  dbExecQuerier
	// chDB is the optional ClickHouse event-archive connection (ADR-0015). Only the restart timestamp-slide uses it; nil when
	// EDR_CLICKHOUSE_DSN is unset (the seeder still enrolls, replays, and verifies against MySQL + the HTTP API).
	chDB   *sql.DB
	client *http.Client
	logger *slog.Logger
}

// newSeeder wires a seeder with a pre-built HTTP client (built in main so config errors surface at the wiring boundary).
func newSeeder(cfg config, db dbExecQuerier, client *http.Client, logger *slog.Logger) *seeder {
	return &seeder{cfg: cfg, db: db, client: client, logger: logger}
}

// newHTTPClient builds the client used for enroll, ingest, and readiness probes. It clones http.DefaultTransport to keep the stock
// connection-pool + timeout tuning. When caCertPath is set, the server's TLS is verified against that PEM (the demo stack's
// self-signed localhost cert) rather than disabling verification; an empty path uses the system trust store.
func newHTTPClient(caCertPath string) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if caCertPath != "" {
		//nolint:gosec // G304: caCertPath is operator-supplied wiring config (a trusted CA path), not untrusted input
		pemBytes, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read ca cert %s: %w", caCertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("ca cert %s: no PEM certificates found", caCertPath)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: httpClientTimeout, Transport: tr}, nil
}

// run executes the full seed. It is safe to re-run: replay is skipped when demo data is already present unless cfg.force is set,
// and on that skip path the existing timestamps are slid forward so the graph still reads as recent activity (refreshTimestamps).
func (s *seeder) run(ctx context.Context) error {
	if err := s.waitReady(ctx); err != nil {
		return fmt.Errorf("server did not become ready: %w", err)
	}

	// On an idempotent re-run (demo data already present, --force off) slide the existing rows forward instead of re-replaying.
	if handled, err := s.maybeRefreshExisting(ctx); handled || err != nil {
		return err
	}

	// Replay each rich captured host (deep real process tree + correlated network_connect/dns_query) and weave its attacks
	// in, so every detection fires inside genuine ambient activity rather than on a 2-event stub host.
	for _, host := range hostManifest {
		if err := s.replayHost(ctx, host); err != nil {
			return fmt.Errorf("replay host %s: %w", host.File, err)
		}
	}

	if err := s.verify(ctx); err != nil {
		return fmt.Errorf("verify demo data: %w", err)
	}
	if err := s.seedUserIfConfigured(ctx); err != nil {
		return err
	}

	s.logger.InfoContext(ctx, "demo seed complete")
	return nil
}

// maybeRefreshExisting handles the idempotent re-run path. When --force is off and the demo data is already present, it slides the
// existing rows forward (so the graph still reads as recent) and reprovisions the SSO user instead of re-replaying the corpus, then
// reports handled=true so run returns without replaying. It reports handled=false when a fresh replay should proceed.
func (s *seeder) maybeRefreshExisting(ctx context.Context) (bool, error) {
	if s.cfg.force {
		return false, nil
	}
	seeded, err := s.alreadySeeded(ctx)
	if err != nil {
		return false, fmt.Errorf("check already-seeded: %w", err)
	}
	if !seeded {
		return false, nil
	}
	// Don't re-replay, but slide the existing rows forward so the graph still reads as recent activity. The persisted
	// demo volume survives restarts, so without this the timestamps stay frozen at the first seed and age out of the UI's
	// last-hour process-tree window, leaving the host view empty after a day or a restart.
	if err := s.refreshTimestamps(ctx); err != nil {
		return true, fmt.Errorf("refresh demo timestamps: %w", err)
	}
	s.logger.InfoContext(ctx, "demo data already present, refreshed timestamps to recent (pass --force to re-seed)")
	return true, s.seedUserIfConfigured(ctx)
}

// buildBlockEnvelope constructs the application_control_block wire envelope the ApplicationControlBlock rule consumes. Payload shape
// mirrors server/rules/internal/catalog/application_control_block.go's applicationControlBlockPayload.
func buildBlockEnvelope(hostID string, pid int, execPath string, tsNs int64) fakeagent.Envelope {
	payload := map[string]any{
		"pid":            pid,
		"path":           execPath,
		"rule_id":        appControlRuleID,
		"rule_type":      appControlRuleType,
		"identifier":     execPath,
		"severity":       appControlSeverity,
		"custom_msg":     appControlMessage,
		"policy_id":      1,
		"policy_version": 1,
	}
	// map[string]any of scalars + strings always marshals; the error is unreachable.
	raw, _ := json.Marshal(payload)
	return fakeagent.Envelope{
		EventID:     randomEventID(),
		HostID:      hostID,
		TimestampNs: tsNs,
		EventType:   appControlEventType,
		Payload:     raw,
	}
}

// enroll posts to /api/enroll and returns the issued host token. Mirrors the agent's enroll contract (server/endpoint/api).
func (s *seeder) enroll(ctx context.Context, hostID, hostname string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"enroll_secret": s.cfg.enrollSecret,
		"hardware_uuid": hostID,
		"hostname":      hostname,
		"agent_version": "demo-seed",
		"os_version":    "macOS 26.0",
	})
	if err != nil {
		return "", err
	}
	//nolint:gosec // G704: serverURL is operator-supplied demo/wiring config, not attacker-controlled input
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.serverURL+"/api/enroll", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req) //nolint:gosec // G704: request targets the operator-configured server URL
	if err != nil {
		return "", fmt.Errorf("POST /api/enroll: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
		return "", fmt.Errorf("POST /api/enroll for %s: HTTP %d (%s)", hostID, resp.StatusCode, bytes.TrimSpace(snippet))
	}
	var er struct {
		HostID    string `json:"host_id"`
		HostToken string `json:"host_token"`
	}
	// Bound the decoded body so an unexpectedly large response cannot exhaust memory.
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&er); err != nil {
		return "", fmt.Errorf("decode enroll response: %w", err)
	}
	if er.HostToken == "" {
		return "", fmt.Errorf("enroll response for %s missing host_token", hostID)
	}
	return er.HostToken, nil
}

// postEnvelopes posts a batch of envelopes to /api/events with the host bearer token.
func (s *seeder) postEnvelopes(ctx context.Context, token string, envs []fakeagent.Envelope) error {
	body, err := json.Marshal(envs)
	if err != nil {
		return err
	}
	//nolint:gosec // G704: serverURL is operator-supplied demo/wiring config, not attacker-controlled input
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.serverURL+"/api/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.client.Do(req) //nolint:gosec // G704: request targets the operator-configured server URL
	if err != nil {
		return fmt.Errorf("POST /api/events: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
		return fmt.Errorf("POST /api/events: HTTP %d (%s)", resp.StatusCode, bytes.TrimSpace(snippet))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// waitReady polls GET /readyz until it returns 200 or readyTimeout elapses.
func (s *seeder) waitReady(ctx context.Context) error {
	var lastErr error
	err := s.poll(ctx, s.cfg.readyTimeout, func() (bool, error) {
		//nolint:gosec // G704: serverURL is operator-supplied demo/wiring config, not attacker-controlled input
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.serverURL+"/readyz", nil)
		if err != nil {
			return false, err
		}
		resp, err := s.client.Do(req) //nolint:gosec // G704: request targets the operator-configured server URL
		if err != nil {
			lastErr = err
			return false, nil // server not up yet; keep polling
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("readyz HTTP %d", resp.StatusCode)
			return false, nil // server up but not ready (e.g. 503 during migrations); keep polling
		}
		return true, nil
	})
	if err != nil && lastErr != nil {
		return fmt.Errorf("%w (last probe error: %w)", err, lastErr)
	}
	return err
}

// seedUserIfConfigured provisions the SSO demo user when a subject is configured; otherwise it is a logged no-op.
func (s *seeder) seedUserIfConfigured(ctx context.Context) error {
	if s.cfg.demoOIDCSubject == "" {
		s.logger.InfoContext(ctx, "no demo OIDC subject configured, skipping SSO demo-user seed")
		return nil
	}
	if err := seedDemoUser(ctx, s.db, s.cfg.demoEmail, s.cfg.demoOIDCSubject, s.cfg.demoRole); err != nil {
		return fmt.Errorf("seed demo user: %w", err)
	}
	s.logger.InfoContext(ctx, "seeded SSO demo user", "email", s.cfg.demoEmail, "role", s.cfg.demoRole)
	return nil
}

// alreadySeeded reports whether the headline detection alert already exists on a demo host, used to make the seeder idempotent
// across restarts. The host scope keeps a real deployment's own credential_keychain_dump alert (a genuine detection, not demo data)
// from convincing a mis-pointed seeder that the demo is already present.
func (s *seeder) alreadySeeded(ctx context.Context) (bool, error) {
	inClause, hostArgs, err := demoHostScope()
	if err != nil {
		return false, err
	}
	var n int
	query := `SELECT COUNT(*) FROM alerts WHERE rule_id = ? AND ` + inClause
	if err := s.db.QueryRowContext(ctx, query, append([]any{keychainRuleID}, hostArgs...)...).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// refreshTimestamps slides every replayed nanosecond timestamp (and the alert "fired at" times stamped from the same wall clock)
// forward so the newest one lands recentTailOffset before now. The replay's shiftEnvelopesToRecent only runs on a fresh seed; on a
// restart against the persisted demo volume the rows keep their original timestamps, which age out of the UI's last-hour
// process-tree window and leave the host view empty. Re-deriving one delta and adding it to every column preserves all relative
// timing (and the device-vs-ingest and event-vs-alert ordering the detail/correlation views depend on), so the demo reads as
// recent activity after every `up` without re-replaying. No-op when no replayed event/process rows exist yet.
func (s *seeder) refreshTimestamps(ctx context.Context) error {
	// Scope every read and write below to the demo's own hosts. The seeder takes an operator-supplied DSN, so an unscoped refresh
	// pointed at a live DB would rewrite real timelines. The IN clause bounds the blast radius to the embedded corpus's host UUIDs,
	// which a real deployment will never contain.
	inClause, hostArgs, err := demoHostScope()
	if err != nil {
		return err
	}

	newestNs, ok, err := s.newestReplayedTimestampNs(ctx, inClause, hostArgs)
	if err != nil {
		return err
	}
	if !ok {
		return nil // no replayed rows yet; nothing to slide
	}
	deltaNs := time.Now().Add(-recentTailOffset).UnixNano() - newestNs
	// alerts carry SQL TIMESTAMP(6) columns; we slide them at whole-second granularity (the alert -> process-tree window the UI
	// anchors on created_at spans minutes, so sub-second precision is irrelevant). deltaSec <= 0 means the data is already at or
	// newer than the target (a quick restart after a fresh seed, or clock skew): nothing to slide, and a backward shift would only
	// un-recent the graph, so skip the redundant writes.
	deltaSec := deltaNs / int64(time.Second)
	if deltaSec <= 0 {
		return nil
	}

	if err := s.applyTimestampSlide(ctx, inClause, hostArgs, deltaNs, deltaSec); err != nil {
		return err
	}

	if err := s.slideArchiveEvents(ctx, inClause, hostArgs, deltaNs); err != nil {
		return err
	}

	s.logger.InfoContext(ctx, "refreshed demo timestamps to recent", "delta_ns", deltaNs)
	return nil
}

// newestReplayedTimestampNs reads the demo hosts' device-clock tail, the anchor for the refresh delta. ok is false when no replayed
// process rows exist yet (a fresh volume), so the caller skips the slide entirely.
//
// Anchor the delta on the device-clock tail only: fork/exec/event timestamps and their ingest stamps. The exit columns are
// deliberately excluded because the process-TTL reconciler (pipeline.ProcessTTLRunner) force-exits long-running processes at
// fork + maxAge, so a stale demo's synthesized exit_time_ns sits ~maxAge PAST the real tail. Anchoring on it would shrink the
// delta by maxAge and leave every fork that-much stale, which is exactly the empty-1h-window symptom this guards against.
// Anchor on the process graph's device-clock tail. Events live in the ClickHouse archive now (ADR-0015), not a MySQL table, but
// the process rows are materialized from those events: fork_time_ns tracks the event timestamp tail and fork_ingested_at_ns the
// server ingest-stamp tail, so the processes columns carry the same anchor the events MAX used to provide.
func (s *seeder) newestReplayedTimestampNs(ctx context.Context, inClause string, hostArgs []any) (int64, bool, error) {
	newestQuery := `
		SELECT GREATEST(
			COALESCE((SELECT MAX(fork_time_ns) FROM processes WHERE ` + inClause + `), 0),
			COALESCE((SELECT MAX(fork_ingested_at_ns) FROM processes WHERE ` + inClause + `), 0),
			COALESCE((SELECT MAX(exec_time_ns) FROM processes WHERE ` + inClause + `), 0)
		)`
	anchorArgs := make([]any, 0, len(hostArgs)*3) // newestQuery references inClause three times
	for range 3 {
		anchorArgs = append(anchorArgs, hostArgs...)
	}
	var newestNs sql.NullInt64
	if err := s.db.QueryRowContext(ctx, newestQuery, anchorArgs...).Scan(&newestNs); err != nil {
		return 0, false, fmt.Errorf("read newest demo timestamp: %w", err)
	}
	if !newestNs.Valid || newestNs.Int64 == 0 {
		return 0, false, nil // no replayed rows yet; nothing to slide
	}
	return newestNs.Int64, true, nil
}

// applyTimestampSlide runs the MySQL half of the refresh in one transaction: shift every replayed process/host/alert timestamp column
// forward and drop the synthesized TTL force-exits. deltaNs slides the nanosecond columns; deltaSec slides the alerts' TIMESTAMP(6)
// columns at whole-second granularity. Every statement carries the demo-host scope.
func (s *seeder) applyTimestampSlide(ctx context.Context, inClause string, hostArgs []any, deltaNs, deltaSec int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin refresh tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op once Commit succeeds

	// NULL + delta stays NULL, so still-running processes keep their open exit columns. Every statement carries the host scope.
	updates := []struct {
		query string
		args  []any
	}{
		{`UPDATE processes SET fork_time_ns = fork_time_ns + ?, fork_ingested_at_ns = fork_ingested_at_ns + ?,
			exec_time_ns = exec_time_ns + ?, exit_time_ns = exit_time_ns + ?, exit_ingested_at_ns = exit_ingested_at_ns + ?,
			last_seen_ns = last_seen_ns + ? WHERE ` + inClause,
			append([]any{deltaNs, deltaNs, deltaNs, deltaNs, deltaNs, deltaNs}, hostArgs...)},
		// Drop the synthesized force-exits: anchoring on the fork tail slides them maxAge into the future, and for a just-refreshed
		// demo the honest reading is "still running" (the forks are now minutes old). The reconciler re-creates them after maxAge,
		// long after anyone is looking at this `up`. Real captured exits (any other reason) keep their shifted, in-the-past values.
		{`UPDATE processes SET exit_time_ns = NULL, exit_ingested_at_ns = NULL, exit_reason = NULL WHERE exit_reason = ? AND ` + inClause,
			append([]any{api.ExitReasonTTLReconciliation}, hostArgs...)},
		{`UPDATE hosts SET last_seen_ns = last_seen_ns + ? WHERE ` + inClause, append([]any{deltaNs}, hostArgs...)},
		{`UPDATE alerts SET created_at = DATE_ADD(created_at, INTERVAL ? SECOND),
			updated_at = DATE_ADD(updated_at, INTERVAL ? SECOND),
			resolved_at = DATE_ADD(resolved_at, INTERVAL ? SECOND) WHERE ` + inClause,
			append([]any{deltaSec, deltaSec, deltaSec}, hostArgs...)},
	}
	for _, u := range updates {
		if _, err := tx.ExecContext(ctx, u.query, u.args...); err != nil {
			return fmt.Errorf("slide demo timestamps: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit timestamp refresh: %w", err)
	}
	return nil
}

// slideArchiveEvents slides the archived events' timestamps by deltaNs so per-process network/DNS correlation stays aligned with the
// shifted process graph (the correlation read windows on ingested_at_ns). No-op when no archive connection was configured (the
// MySQL-only / released-image path). ClickHouse has no transactional UPDATE: ALTER ... UPDATE is a mutation, and mutations_sync = 1
// makes the seeder wait for it to finish so a follow-up demo read sees the shift. The demo dataset is tiny, so it completes quickly.
func (s *seeder) slideArchiveEvents(ctx context.Context, inClause string, hostArgs []any, deltaNs int64) error {
	if s.chDB == nil {
		return nil
	}
	chPrefix := "ALTER TABLE events UPDATE timestamp_ns = timestamp_ns + ?, ingested_at_ns = ingested_at_ns + ? WHERE "
	// inClause is a generated "?,?,..." placeholder list, never user input, and the host ids bind as ? args; same shape as the MySQL
	// UPDATEs above (gosec does not flag those only because they pass through the updates slice).
	chQuery := chPrefix + inClause + " SETTINGS mutations_sync = 1" //nolint:gosec // G202: placeholder concat, args bound as ?
	chArgs := append([]any{deltaNs, deltaNs}, hostArgs...)
	if _, err := s.chDB.ExecContext(ctx, chQuery, chArgs...); err != nil {
		return fmt.Errorf("slide demo event timestamps in clickhouse: %w", err)
	}
	return nil
}

// waitForProcess polls until at least one process row exists for the host/pid, or verifyTimeout elapses.
func (s *seeder) waitForProcess(ctx context.Context, hostID string, pid int) error {
	return s.poll(ctx, s.cfg.verifyTimeout, func() (bool, error) {
		var n int
		err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM processes WHERE host_id = ? AND pid = ?`, hostID, pid).Scan(&n)
		if err != nil {
			return false, err
		}
		return n > 0, nil
	})
}

// verify polls until the processor has materialised a process graph, a fired alert for EVERY woven attack's expected rule, and at
// least one app-control alert, or verifyTimeout elapses. Per rule rather than "any detection alert": a processing race can drop
// exactly one rule's alert while the rest fire (the 2026-07-02 nightly lost only sudoers_tamper), and an any-alert predicate lets
// the seeder exit 0 on that partial state, deferring the failure to the Playwright smoke where it is much harder to debug.
func (s *seeder) verify(ctx context.Context) error {
	expected := expectedDetectionRules()
	inClause, hostArgs, err := demoHostScope()
	if err != nil {
		return err
	}
	var last demoCounts
	err = s.poll(ctx, s.cfg.verifyTimeout, func() (bool, error) {
		c, err := s.counts(ctx, inClause, hostArgs)
		if err != nil {
			return false, err
		}
		last = c
		s.logger.DebugContext(ctx, "verify counts", "processes", c.processes,
			"detection_alerts", c.detectionAlerts, "app_control_alerts", c.appControlAlerts,
			"missing_rules", missingRules(expected, c.detectionRuleIDs))
		return c.processes > 0 && c.appControlAlerts > 0 && len(missingRules(expected, c.detectionRuleIDs)) == 0, nil
	})
	if err != nil {
		return fmt.Errorf("%w (processes=%d detection_alerts=%d app_control_alerts=%d missing_rules=%v)",
			err, last.processes, last.detectionAlerts, last.appControlAlerts, missingRules(expected, last.detectionRuleIDs))
	}
	return nil
}

// expectedDetectionRules returns the catalog rule ids the woven attacks are expected to trip, in manifest order.
func expectedDetectionRules() []string {
	var rules []string
	for _, h := range hostManifest {
		for _, atk := range h.Attacks {
			if atk.Kind == kindAttack && atk.ExpectRule != "" {
				rules = append(rules, atk.ExpectRule)
			}
		}
	}
	return rules
}

// missingRules returns the expected rule ids that have no fired alert yet, preserving expected order for a stable error message.
func missingRules(expected []string, fired map[string]bool) []string {
	var missing []string
	for _, r := range expected {
		if !fired[r] {
			missing = append(missing, r)
		}
	}
	return missing
}

// demoCounts is the materialised-data tally verify checks.
type demoCounts struct {
	processes        int
	detectionAlerts  int
	appControlAlerts int
	// detectionRuleIDs is the set of rule ids with at least one detection-source alert, so verify can assert per expected rule.
	detectionRuleIDs map[string]bool
}

// counts reads the current process + alert tallies from the database, scoped by the caller's demo-host IN clause so pre-existing
// rows on a real deployment (or leftovers from another tool sharing the DB) can never satisfy the verify predicate.
func (s *seeder) counts(ctx context.Context, inClause string, hostArgs []any) (demoCounts, error) {
	var c demoCounts
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM processes WHERE `+inClause, hostArgs...).Scan(&c.processes); err != nil {
		return c, fmt.Errorf("count processes: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alerts WHERE source = 'detection' AND `+inClause, hostArgs...).Scan(&c.detectionAlerts); err != nil {
		return c, fmt.Errorf("count detection alerts: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alerts WHERE source = 'application_control' AND `+inClause, hostArgs...).Scan(&c.appControlAlerts); err != nil {
		return c, fmt.Errorf("count app-control alerts: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT rule_id FROM alerts WHERE source = 'detection' AND `+inClause, hostArgs...)
	if err != nil {
		return c, fmt.Errorf("list fired detection rules: %w", err)
	}
	defer rows.Close()
	c.detectionRuleIDs = make(map[string]bool)
	for rows.Next() {
		var ruleID string
		if err := rows.Scan(&ruleID); err != nil {
			return c, fmt.Errorf("scan fired detection rule: %w", err)
		}
		c.detectionRuleIDs[ruleID] = true
	}
	if err := rows.Err(); err != nil {
		return c, fmt.Errorf("iterate fired detection rules: %w", err)
	}
	return c, nil
}

// poll runs cond on cfg.pollInterval until it returns true, cond errors, the context is cancelled, or timeout elapses.
func (s *seeder) poll(ctx context.Context, timeout time.Duration, cond func() (bool, error)) error {
	deadline := time.Now().Add(timeout)
	for {
		ok, err := cond()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("condition not met within %s", timeout)
		}
		if err := sleep(ctx, s.cfg.pollInterval); err != nil {
			return err
		}
	}
}

// sleep is a context-aware sleep.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// randomEventID returns a 32-char lower-hex random id for the fabricated block event.
func randomEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("demo-seed: crypto/rand.Read: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
