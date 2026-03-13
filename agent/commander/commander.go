// Package commander polls the server for pending commands and executes them.
package commander

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// Config holds commander settings.
type Config struct {
	ServerURL string
	APIKey    string
	HostID    string
	Interval  time.Duration
}

// Commander polls the server for pending commands and dispatches them.
type Commander struct {
	cfg    Config
	client *http.Client
}

// New creates a Commander.
func New(cfg Config) *Commander {
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	return &Commander{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
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
		log.Printf("commander: fetch pending: %v", err)
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
	// Acknowledge the command first.
	if err := c.updateStatus(ctx, cmd.ID, "acked", nil); err != nil {
		log.Printf("commander: ack command %d: %v", cmd.ID, err)
		return
	}

	switch cmd.CommandType {
	case "kill_process":
		c.executeKill(ctx, cmd)
	default:
		if err := c.updateStatus(ctx, cmd.ID, "failed", marshalResult("unknown command type: "+cmd.CommandType)); err != nil {
			log.Printf("commander: fail command %d: %v", cmd.ID, err)
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

	log.Printf("commander: killing PID %d", payload.PID)

	// Send SIGKILL.
	err := syscall.Kill(payload.PID, syscall.SIGKILL)
	if err != nil {
		if updateErr := c.updateStatus(ctx, cmd.ID, "failed", marshalResult(err.Error())); updateErr != nil {
			log.Printf("commander: report kill failure for command %d: %v", cmd.ID, updateErr)
		}
		return
	}

	successResult, _ := json.Marshal(map[string]int{"killed_pid": payload.PID})
	if err := c.updateStatus(ctx, cmd.ID, "completed", successResult); err != nil {
		log.Printf("commander: report kill success for command %d: %v", cmd.ID, err)
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
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
}
