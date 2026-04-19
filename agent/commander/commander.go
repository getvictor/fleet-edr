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

// Config holds commander settings.
type Config struct {
	ServerURL string
	// TokenFn returns the current bearer token at request time. Nil means "no auth header".
	TokenFn func() string
	// OnAuthFail is called on HTTP 401 so the agent can trigger a re-enroll. Nil is allowed.
	OnAuthFail func(ctx context.Context)
	HostID     string
	Interval   time.Duration
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
	reqURL := fmt.Sprintf("%s/api/v1/commands?host_id=%s&status=pending", c.cfg.ServerURL, url.QueryEscape(c.cfg.HostID))

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
	default:
		if err := c.updateStatus(ctx, cmd.ID, "failed", marshalResult("unknown command type: "+cmd.CommandType)); err != nil {
			c.logger.ErrorContext(ctx, "commander fail", "cmd_id", cmd.ID, "err", err)
		}
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
	reqURL := fmt.Sprintf("%s/api/v1/commands/%d", c.cfg.ServerURL, cmdID)

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
