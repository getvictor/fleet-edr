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

// defaultPollInterval is the fallback Interval when Config.Interval is zero.
// Mirrored as commanderPollInterval in agent/cmd/fleet-edr-agent.
const defaultPollInterval = 5 * time.Second

// invalidPayloadPrefix is the reason prefix every command handler emits when json.Unmarshal of cmd.Payload fails. Centralised so the
// wire shape stays stable across handlers.
const invalidPayloadPrefix = "invalid payload: "

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
	// RotateTokenFn applies a rotate_token command's new bearer to the agent's persisted state (issue #86). Nil means rotate_token is
	// reported as failed; this is the right behaviour for tests / dry-runs that don't carry a real enrollment provider. Production wires
	// enrollment.TokenProvider.Rotate.
	RotateTokenFn func(ctx context.Context, newToken string) error
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
		cfg.Interval = defaultPollInterval
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

// setApplicationControlPayload mirrors server/rules/api.SetApplicationControlPayload. Field names + json tags are load-bearing:
// the extension parses the same JSON bytes and the byte-shape must match across all three sides. The commander's job is envelope
// validation (policy_id present, version positive, rules is a JSON array) before handing the raw bytes off to the extension;
// the per-rule decode happens on the extension side, which is the only consumer that actually walks the rules list. Gating on the
// rules-is-an-array check here prevents reporting `completed` for a payload the extension will silently fail to decode.
type setApplicationControlPayload struct {
	PolicyID      int64 `json:"policy_id"`
	PolicyVersion int64 `json:"policy_version"`
	// Rules is decoded as json.RawMessage so the commander doesn't need to know the rule shape; the extension is the source of truth for
	// the per-rule schema and the commander only forwards the bytes it received.
	Rules json.RawMessage `json:"rules"`
}

// rotateTokenPayload mirrors the JSON the server emits when issuing a rotate_token command (issue #86). The new bearer is in
// cleartext; transport security is provided by TLS on the host-token-protected command-poll endpoint, so receiving the new token here
// is no worse than the original enrollment response.
type rotateTokenPayload struct {
	NewToken string `json:"new_token"`
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
	case "set_application_control":
		c.executeSetApplicationControl(ctx, cmd)
	case "rotate_token":
		c.executeRotateToken(ctx, cmd)
	default:
		if err := c.updateStatus(ctx, cmd.ID, "failed", marshalResult("unknown command type: "+cmd.CommandType)); err != nil {
			c.logger.ErrorContext(ctx, "commander fail", "cmd_id", cmd.ID, "err", err)
		}
	}
}

// executeSetApplicationControl forwards the raw command payload to the ESF
// extension over XPC. Result shape on success:
// {"policy_id": P, "policy_version": V} so operators can confirm via
// `GET /commands/{id}` that the agent applied the snapshot it was meant to.
//
// Envelope validation only: the per-rule shape is the extension's
// responsibility. Forwarding the raw bytes (rather than re-marshalling)
// keeps the wire shape byte-identical across server → agent → extension so
// a future schema tightening that fails on one side surfaces on the same
// commit.
func (c *Commander) executeSetApplicationControl(ctx context.Context, cmd command) {
	var payload setApplicationControlPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult(invalidPayloadPrefix+err.Error()))
		return
	}
	if payload.PolicyID <= 0 {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("payload missing or invalid policy_id"))
		return
	}
	if payload.PolicyVersion <= 0 {
		// Versioning is the ordering guard for snapshot state on the extension; a zero/negative version would either mask an
		// out-of-order delivery or reflect a hand-queued test command that shouldn't be acted on. Fail fast so the server-
		// side audit trail attributes the error to its source rather than to the XPC layer returning opaque decode errors from
		// the extension.
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("invalid policy_version"))
		return
	}
	// Validate that rules is present AND a JSON array (empty array allowed). Without this gate, payloads with missing/null/non-array rules
	// slip past the envelope check because the json.RawMessage decode accepts any well-formed JSON value, the extension then fails to
	// decode silently, and the server sees `completed` for a snapshot the extension never applied.
	if !isJSONArray(payload.Rules) {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("payload missing or invalid rules array"))
		return
	}
	if c.cfg.ApplicationControlSender == nil {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("application control sender not configured"))
		return
	}

	c.logger.InfoContext(ctx, "commander set_application_control",
		"cmd_id", cmd.ID,
		"edr.app_control.policy_id", payload.PolicyID,
		"edr.app_control.policy_version", payload.PolicyVersion,
	)

	// Forward the raw JSON bytes so the extension parses the same shape the server wrote. Re-marshalling would introduce drift in field
	// ordering / casing that a future schema tightening could catch on one side but not the other.
	if err := c.cfg.ApplicationControlSender.SendApplicationControl([]byte(cmd.Payload)); err != nil {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("xpc send: "+err.Error()))
		return
	}

	// The send is async: completing the command here does NOT mean the extension has successfully applied the snapshot. The demo cut
	// intentionally stops short of an extension-side ack; the audit trail of "command completed on agent" is sufficient for now. A future
	// revision can add a round-trip ack with the actually-applied version.
	result, _ := json.Marshal(map[string]any{
		"policy_id":      payload.PolicyID,
		"policy_version": payload.PolicyVersion,
	})
	if err := c.updateStatus(ctx, cmd.ID, "completed", result); err != nil {
		c.logger.ErrorContext(ctx, "commander report set_application_control success", "cmd_id", cmd.ID, "err", err)
	}
}

// executeRotateToken applies the server-issued new bearer to the agent's persisted state, then acks the command. Ordering is
// load-bearing: the ack PUT must happen AFTER the rotate succeeds, because the ack itself is bearer-authenticated and the server has
// already pre-flipped its active token to the new value (the old token only verifies during the grace window). Acking with the old
// token still works for ~5 minutes; acking with the new token works indefinitely. So the natural order (rotate first, ack second)
// is correct.
func (c *Commander) executeRotateToken(ctx context.Context, cmd command) {
	var payload rotateTokenPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult(invalidPayloadPrefix+err.Error()))
		return
	}
	if payload.NewToken == "" {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("payload missing new_token"))
		return
	}
	if c.cfg.RotateTokenFn == nil {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("rotate not configured"))
		return
	}
	if err := c.cfg.RotateTokenFn(ctx, payload.NewToken); err != nil {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult("apply rotate: "+err.Error()))
		return
	}
	c.logger.InfoContext(ctx, "commander rotate_token applied", "cmd_id", cmd.ID)
	if err := c.updateStatus(ctx, cmd.ID, "completed", nil); err != nil {
		c.logger.ErrorContext(ctx, "commander report rotate_token success", "cmd_id", cmd.ID, "err", err)
	}
}

func (c *Commander) executeKill(ctx context.Context, cmd command) {
	var payload killPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		_ = c.updateStatus(ctx, cmd.ID, "failed", marshalResult(invalidPayloadPrefix+err.Error()))
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

// isJSONArray reports whether raw is a JSON array (including the empty array). Used by the set_application_control envelope check to
// reject payloads with missing or null `rules` fields, which would otherwise slip through json.Unmarshal-into-json.RawMessage and only
// fail at extension decode time after the server has already seen `completed`.
func isJSONArray(raw json.RawMessage) bool {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
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
