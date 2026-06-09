package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

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
	cfg    config
	db     dbExecQuerier
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

// run executes the full seed. It is safe to re-run: replay is skipped when demo data is already present unless cfg.force is set.
func (s *seeder) run(ctx context.Context) error {
	if err := s.waitReady(ctx); err != nil {
		return fmt.Errorf("server did not become ready: %w", err)
	}

	scenarios, err := loadScenarios()
	if err != nil {
		return err
	}

	if !s.cfg.force {
		seeded, err := s.alreadySeeded(ctx)
		if err != nil {
			return fmt.Errorf("check already-seeded: %w", err)
		}
		if seeded {
			s.logger.InfoContext(ctx, "demo data already present, skipping replay (pass --force to re-seed)")
			return s.seedUserIfConfigured(ctx)
		}
	}

	for _, sc := range scenarios {
		if err := s.replay(ctx, sc); err != nil {
			return fmt.Errorf("replay %s: %w", sc.File, err)
		}
	}

	// Rich captured hosts: deep real process trees with correlated network_connect + dns_query that the
	// attack/noise scenarios lack. Replayed after the scenarios so the demo opens on populated, realistic hosts.
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

// replay enrols the scenario's host, posts its events directly to the ingest API, and for app-control scenarios fabricates the
// follow-up block event.
func (s *seeder) replay(ctx context.Context, sc demoScenario) error {
	hostID := sc.Scenario.Host.ID
	token, err := s.enroll(ctx, hostID, sc.Scenario.Host.Hostname)
	if err != nil {
		return err
	}

	base := time.Now()
	if err := sc.Scenario.PostDirect(ctx, s.cfg.serverURL, token,
		fakeagent.WithHTTPClient(s.client), fakeagent.WithStartTime(base)); err != nil {
		return err
	}
	s.logger.InfoContext(ctx, "replayed scenario",
		"file", sc.File, "host_id", hostID, "kind", string(sc.Kind), "events", len(sc.Scenario.Timeline))

	if sc.Kind == kindAppControl {
		return s.postAppControlBlock(ctx, sc, token, base)
	}
	return nil
}

// postAppControlBlock fabricates and posts the application_control_block event for an app-control scenario. The block rule resolves
// the event's pid against the materialised graph, so it first waits for the scenario's exec to land; otherwise the rule would skip
// the event permanently (the processor evaluates each event once).
func (s *seeder) postAppControlBlock(ctx context.Context, sc demoScenario, token string, base time.Time) error {
	pid, execPath, ok := firstExec(sc.Scenario)
	if !ok {
		return fmt.Errorf("app-control scenario %s has no exec event", sc.File)
	}
	hostID := sc.Scenario.Host.ID

	if err := s.waitForProcess(ctx, hostID, pid); err != nil {
		return fmt.Errorf("app-control process pid %d never materialised: %w", pid, err)
	}

	// Stamp the block one second past the scenario start so it sits after the fork/exec; the scenario emits no exit, so the live
	// process resolves at this timestamp.
	blockTS := base.Add(time.Second).UnixNano()
	env := buildBlockEnvelope(hostID, pid, execPath, blockTS)
	if err := s.postEnvelopes(ctx, token, []fakeagent.Envelope{env}); err != nil {
		return fmt.Errorf("post application_control_block event: %w", err)
	}
	s.logger.InfoContext(ctx, "posted application-control block", "host_id", hostID, "pid", pid, "path", execPath)
	return nil
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

// alreadySeeded reports whether the headline detection alert already exists, used to make the seeder idempotent across restarts.
func (s *seeder) alreadySeeded(ctx context.Context) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE rule_id = ?`, keychainRuleID).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
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

// verify polls until the processor has materialised a process graph, at least one detection alert, and at least one app-control
// alert, or verifyTimeout elapses.
func (s *seeder) verify(ctx context.Context) error {
	var last demoCounts
	err := s.poll(ctx, s.cfg.verifyTimeout, func() (bool, error) {
		c, err := s.counts(ctx)
		if err != nil {
			return false, err
		}
		last = c
		s.logger.DebugContext(ctx, "verify counts",
			"processes", c.processes, "detection_alerts", c.detectionAlerts, "app_control_alerts", c.appControlAlerts)
		return c.processes > 0 && c.detectionAlerts > 0 && c.appControlAlerts > 0, nil
	})
	if err != nil {
		return fmt.Errorf("%w (processes=%d detection_alerts=%d app_control_alerts=%d)",
			err, last.processes, last.detectionAlerts, last.appControlAlerts)
	}
	return nil
}

// demoCounts is the materialised-data tally verify checks.
type demoCounts struct {
	processes        int
	detectionAlerts  int
	appControlAlerts int
}

// counts reads the current process + alert tallies from the database.
func (s *seeder) counts(ctx context.Context) (demoCounts, error) {
	var c demoCounts
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM processes`).Scan(&c.processes); err != nil {
		return c, fmt.Errorf("count processes: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alerts WHERE source = 'detection'`).Scan(&c.detectionAlerts); err != nil {
		return c, fmt.Errorf("count detection alerts: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM alerts WHERE source = 'application_control'`).Scan(&c.appControlAlerts); err != nil {
		return c, fmt.Errorf("count app-control alerts: %w", err)
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
