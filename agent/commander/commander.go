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
	"time"
)

// defaultPollInterval is the fallback Interval when Config.Interval is zero.
// Mirrored as commanderPollInterval in agent/cmd/fleet-edr-agent.
const defaultPollInterval = 5 * time.Second

// ApplicationControlSender forwards a raw application-control snapshot JSON payload to the ESF extension over XPC. The commander stays
// decoupled from the concrete receiver so tests can supply a recording double. Nil is allowed (set_application_control commands are
// then reported as `failed` with a clear reason), matching the pre-step-1 commander shape.
type ApplicationControlSender interface {
	SendApplicationControl(payload []byte) error
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
	// ApplicationControlSender is the XPC bridge to the ESF extension. Used by the set_application_control command handler; nil means
	// "commander cannot apply snapshot updates" and the handler will report the command failed with a clear reason.
	ApplicationControlSender ApplicationControlSender
	// StreamConnected, when set, lets the commander defer to the persistent control channel: while it returns true the poll is skipped
	// (the gateway pushes commands in real time), and the poll resumes the moment the stream drops. Nil means "always poll" (the control
	// channel is disabled), which is the degraded floor.
	StreamConnected func() bool
	// Ledger is the durable dedup store shared with the control client so a command executed on the push path is not re-executed by the
	// poll path after a stream drop (issue #558). Nil disables dedup (the poll path then relies only on the server's pending filter).
	Ledger Ledger
}

// Commander polls the server for pending commands and dispatches them.
type Commander struct {
	cfg      Config
	client   *http.Client
	executor *Executor
	logger   *slog.Logger
}

// New creates a Commander. The client should already be wrapped with otelhttp.NewTransport if
// trace propagation is desired; nil gets a vanilla 10s-timeout client.
func New(cfg Config, client *http.Client, logger *slog.Logger) *Commander {
	if cfg.Interval == 0 {
		cfg.Interval = defaultPollInterval
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Commander{
		cfg:      cfg,
		client:   client,
		executor: NewExecutor(cfg.ApplicationControlSender, cfg.Ledger, logger),
		logger:   logger,
	}
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
	// Defer to the persistent control channel while it is connected: it pushes commands in real time, so polling would only race it and
	// produce invalid-transition noise on already-acked commands. The poll is the degraded floor, used while the stream is down.
	if c.cfg.StreamConnected != nil && c.cfg.StreamConnected() {
		return
	}
	commands, err := c.fetchPending(ctx)
	if err != nil {
		c.logger.WarnContext(ctx, "commander fetch pending", "err", err)
		return
	}

	for _, cmd := range commands {
		c.dispatch(ctx, cmd)
	}
}

func (c *Commander) fetchPending(ctx context.Context) ([]Command, error) {
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

	var commands []Command
	if err := json.NewDecoder(resp.Body).Decode(&commands); err != nil {
		return nil, fmt.Errorf("decode commands: %w", err)
	}
	return commands, nil
}

func (c *Commander) dispatch(ctx context.Context, cmd Command) {
	c.executor.Execute(ctx, cmd, c.report(cmd.ID))
}

// report adapts the executor's outcome callback to the poll transport: each status transition is a PUT /api/commands/{id}.
func (c *Commander) report(id int64) ReportFunc {
	return func(ctx context.Context, status string, result json.RawMessage) error {
		return c.updateStatus(ctx, id, status, result)
	}
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

	// Surface 401 to the enrollment package here too. fetchPending already does this on its poll loop, but a revoked token can show up
	// between a fetch and the following ack/complete PUT. Without this call, recovery waits until the next poll tick.
	if resp.StatusCode == http.StatusUnauthorized && c.cfg.OnAuthFail != nil {
		c.cfg.OnAuthFail(ctx)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
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
