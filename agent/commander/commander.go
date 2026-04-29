// Package commander polls the server for pending commands and executes them.
package commander

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// PolicySender forwards a raw policy JSON payload to the ESF extension over XPC. The
// commander stays decoupled from the concrete receiver so tests can supply a recording
// double. Nil is allowed (policy commands are then reported as `failed` with a clear
// reason), matching the pre-Phase-2 commander which reported unknown command types.
type PolicySender interface {
	SendPolicy(payload []byte) error
}

// Config holds commander settings.
type Config struct {
	ServerURL string
	// TokenFn returns the current bearer token at request time. Nil means "no auth header".
	TokenFn func() string
	// OnAuthFail is called on HTTP 401 so the agent can trigger a re-enroll. Nil is allowed.
	OnAuthFail func(ctx context.Context)
	HostID     string
	Interval   time.Duration
	// PolicySender is the XPC bridge to the ESF extension. Used by the set_blocklist
	// command handler; nil means "commander cannot apply policy updates" and the
	// handler will report the command failed with a clear reason.
	PolicySender PolicySender
}

// Commander polls the server for pending commands and dispatches them.
type Commander struct {
	cfg    Config
	client *http.Client
	logger *slog.Logger
}

// New creates a Commander. The client should already be wrapped with otelhttp.NewTransport if
// trace propagation is desired; nil gets a vanilla 10s-timeout client.
func New(cfg Config, client *http.Client, logger *slog.Logger) *Commander {
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Commander{
		cfg:    cfg,
		client: client,
		logger: logger,
	}
}

// command mirrors the server-side Command struct (fields we need).
type command struct {
	ID          int64           `json:"id"`
	HostID      string          `json:"host_id"`
	CommandType string          `json:"command_type"`
	Payload     json.RawMessage `json:"payload"`
	Status      string          `json:"status"`
}

type killPayload struct {
	PID int `json:"pid"`
}

// setBlocklistPayload mirrors server/admin.policyCommandPayload. Field ordering + names
// are load-bearing: the extension side parses the same JSON.
type setBlocklistPayload struct {
	Name    string   `json:"name"`
	Version int64    `json:"version"`
	Paths   []string `json:"paths"`
	Hashes  []string `json:"hashes"`
}

type statusUpdate struct {
	Status string          `json:"status"`
	Result json.RawMessage `json:"result,omitempty"`
}

// Run polls for pending commands and executes them until the context is cancelled.
func (c *Commander) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			c.pollAndDispatch(ctx)
		}
	}
}

func (c *Commander) pollAndDispatch(ctx context.Context) {
	commands, err := c.fetchPending(ctx)
	if err != nil {
		c.logger.WarnContext(ctx, "commander fetch pending", "err", err)
		return
	}

	for _, cmd := range commands {
		c.dispatch(ctx, cmd)
	}
}

func (c *Commander) fetchPending(ctx context.Context) ([]command, error) {
	reqURL := fmt.Sprintf("%s/api/commands?host_id=%s&status=pending", c.cfg.ServerURL, url.QueryEscape(c.cfg.HostID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized && c.cfg.OnAuthFail != nil {
		c.cfg.OnAuthFail(ctx)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var commands []command
	if err := json.NewDecoder(resp.Body).Decode(&commands); err != nil {
		return nil, fmt.Errorf("decode commands: %w", err)
	}
	return commands, nil
}

func (c *Commander) dispatch(ctx context.Context, cmd command) {
	if err := c.updateStatus(ctx, cmd.ID, "acked", nil); err != nil {
		c.logger.ErrorContext(ctx, "commander ack", "cmd_id", cmd.ID, "err", err)
		return
	}

	switch cmd.CommandType {
	case "kill_process":
		c.executeKill(ctx, cmd)
	case "set_blocklist":
		c.executeSetBlocklist(ctx, cmd)
	default:
		if err := c.updateStatus(ctx, cmd.ID, "failed", marshalResult("unknown command type: "+cmd.CommandType)); err != nil {
			c.logger.ErrorContext(ctx, "commander fail", "cmd_id", cmd.ID, "err", err)
		}
	}
}

// executeSetBlocklist forwards the raw command payload to the ESF extension over XPC.
// Result shape on success: {"version": N, "applied_paths": K} so operators can confirm
// via `GET /commands/{id}` exactly which version each host applied.
func (c *Commander) executeSetBlocklist(ctx context.Context, cmd command) {
	var payload setBlocklistPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("invalid payload: "+err.Error()))
		return
	}
	if payload.Name == "" {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("payload missing name"))
		return
	}
	if payload.Version <= 0 {
		// Versioning is the ordering guard for blocklist state on the extension; a
		// zero/negative version would either mask an out-of-order delivery or reflect a
		// hand-queued test command that shouldn't be acted on. Fail fast so the server-
		// side audit trail attributes the error to its source rather than to the XPC
		// layer returning opaque decode errors from the extension.
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("invalid policy version"))
		return
	}
	if c.cfg.PolicySender == nil {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("policy sender not configured"))
		return
	}

	c.logger.InfoContext(ctx, "commander set_blocklist",
		"cmd_id", cmd.ID,
		"edr.policy.version", payload.Version,
		"edr.policy.path_count", len(payload.Paths),
	)

	// Forward the raw JSON bytes so the extension parses the same shape the server wrote.
	// Re-marshalling would introduce drift in field ordering / casing that a future schema
	// tightening could catch on one side but not the other.
	if err := c.cfg.PolicySender.SendPolicy([]byte(cmd.Payload)); err != nil {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("xpc send: "+err.Error()))
		return
	}

	// The send is async — completing the command here does NOT mean the extension has
	// successfully applied the policy. Phase 2 intentionally stops short of an
	// extension-side ack; the audit trail of "command completed on agent" is sufficient
	// for MVP. v1.1 adds a round-trip ack with the actually-applied version.
	result, _ := json.Marshal(map[string]any{
		"version":       payload.Version,
		"applied_paths": len(payload.Paths),
	})
	if err := c.updateStatus(ctx, cmd.ID, "completed", result); err != nil {
		c.logger.ErrorContext(ctx, "commander report set_blocklist success", "cmd_id", cmd.ID, "err", err)
	}
}

func (c *Commander) executeKill(ctx context.Context, cmd command) {
	var payload killPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("invalid payload: "+err.Error()))
		return
	}

	if payload.PID <= 0 {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("invalid pid"))
		return
	}

	c.logger.InfoContext(ctx, "commander kill_process", "pid", payload.PID, "cmd_id", cmd.ID)

	if err := syscall.Kill(payload.PID, syscall.SIGKILL); err != nil {
		if updateErr := c.updateStatus(ctx, cmd.ID, "failed", marshalResult(err.Error())); updateErr != nil {
			c.logger.ErrorContext(ctx, "commander report kill failure", "cmd_id", cmd.ID, "err", updateErr)
		}
		return
	}

	successResult, _ := json.Marshal(map[string]int{"killed_pid": payload.PID})
	if err := c.updateStatus(ctx, cmd.ID, "completed", successResult); err != nil {
		c.logger.ErrorContext(ctx, "commander report kill success", "cmd_id", cmd.ID, "err", err)
	}
}

// marshalResult builds a properly-escaped JSON result with an error field.
func marshalResult(errMsg string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"error": errMsg})
	return b
}

func (c *Commander) updateStatus(ctx context.Context, cmdID int64, status string, result json.RawMessage) error {
	reqURL := fmt.Sprintf("%s/api/commands/%d", c.cfg.ServerURL, cmdID)

	update := statusUpdate{Status: status, Result: result}
	body, err := json.Marshal(update)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	// Surface 401 to the enrollment package here too. fetchPending already does this on its
	// poll loop, but a revoked token can show up between a fetch and the following ack/complete
	// PUT — without this call, recovery waits until the next poll tick.
	if resp.StatusCode == http.StatusUnauthorized && c.cfg.OnAuthFail != nil {
		c.cfg.OnAuthFail(ctx)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

func (c *Commander) setAuth(req *http.Request) {
	if c.cfg.TokenFn != nil {
		if tok := c.cfg.TokenFn(); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
}
