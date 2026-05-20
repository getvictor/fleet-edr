package fakeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Envelope is the wire shape this library emits per timeline event. Matches schema/events.json: the server's ingest endpoint and
// the M2 headless binary's control plane both accept this exact shape.
type Envelope struct {
	EventID     string          `json:"event_id"`
	HostID      string          `json:"host_id"`
	TimestampNs int64           `json:"timestamp_ns"`
	EventType   string          `json:"event_type"`
	Payload     json.RawMessage `json:"payload"`
}

// Envelopes deterministically materialises the scenario's timeline into wire envelopes. Pure computation; no I/O. Useful for golden
// tests and for callers that want to drive the envelopes themselves (e.g. M10's batch tooling).
func (s *Scenario) Envelopes(opts ...Option) ([]Envelope, error) {
	cfg := newRunConfig(opts)
	hostID := s.Host.ID
	if cfg.hostIDOverride != "" {
		hostID = cfg.hostIDOverride
	}
	out := make([]Envelope, 0, len(s.Timeline))
	for i, ev := range s.Timeline {
		payload, err := buildPayload(ev)
		if err != nil {
			return nil, fmt.Errorf("timeline[%d] %s: %w", i, ev.Type, err)
		}
		ts := cfg.startTime.Add(time.Duration(ev.At)).UnixNano()
		out = append(out, Envelope{
			EventID:     cfg.idGenerator(),
			HostID:      hostID,
			TimestampNs: ts,
			EventType:   ev.Type,
			Payload:     payload,
		})
	}
	return out, nil
}

// FeedControlPlane delivers each envelope to the M2 headless agent's POST /event endpoint over a unix socket. Used by the M4
// integration test and by manual scenario drivers. Returns the first error from the control plane; subsequent envelopes are not
// attempted (the test is interested in the failing case, not in continuing past it).
//
// Honours WithSpeed: a non-zero multiplier sleeps between envelopes to mimic real-time pacing; the default 0 fires every envelope
// back-to-back which is what tests want.
func (s *Scenario) FeedControlPlane(ctx context.Context, socketPath string, opts ...Option) error {
	cfg := newRunConfig(opts)
	envelopes, err := s.Envelopes(opts...)
	if err != nil {
		return err
	}
	client := unixSocketHTTPClient(socketPath)
	url := "http://unix/event"

	prev := time.Duration(0)
	for i, env := range envelopes {
		if cfg.speedMultiplier > 0 && i > 0 {
			gap := time.Duration(s.Timeline[i].At) - prev
			if err := sleepCtx(ctx, time.Duration(float64(gap)/cfg.speedMultiplier)); err != nil {
				return err
			}
		}
		prev = time.Duration(s.Timeline[i].At)
		if err := postOne(ctx, client, url, env); err != nil {
			return fmt.Errorf("FeedControlPlane envelope %d (%s): %w", i, env.EventType, err)
		}
	}
	return nil
}

// PostDirect bypasses the agent entirely and POSTs envelope batches to baseURL + /api/events with a bearer token. Used by Playwright
// fixtures that don't need to exercise the queue + uploader path (auth + RBAC tests, mostly) and by M10's bulk corpus replay.
//
// Honours WithBatchSize. Does NOT honour WithSpeed: batches are flushed as fast as the server can accept them.
func (s *Scenario) PostDirect(ctx context.Context, baseURL, token string, opts ...Option) error {
	cfg := newRunConfig(opts)
	envelopes, err := s.Envelopes(opts...)
	if err != nil {
		return err
	}
	client := defaultHTTPClient()
	url := baseURL + "/api/events"

	for start := 0; start < len(envelopes); start += cfg.batchSize {
		end := min(start+cfg.batchSize, len(envelopes))
		body, err := json.Marshal(envelopes[start:end])
		if err != nil {
			return fmt.Errorf("PostDirect marshal batch %d:%d: %w", start, end, err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("PostDirect batch %d:%d: %w", start, end, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("PostDirect batch %d:%d: server returned HTTP %d", start, end, resp.StatusCode)
		}
	}
	return nil
}

// postOne sends one envelope to the headless binary's POST /event handler. The handler accepts a single envelope per call; that
// matches the production receiver's one-event-at-a-time semantics (each XPC message carries one event).
func postOne(ctx context.Context, client *http.Client, url string, env Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("control plane returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// HTTP-client timeouts. Unix socket is local so 5s is generous; PostDirect talks to a remote server and gets a longer budget.
const (
	unixSocketHTTPTimeout = 5 * time.Second
	postDirectHTTPTimeout = 30 * time.Second
)

// unixSocketHTTPClient builds an http.Client whose transport dials the given unix socket regardless of the URL host. The
// "http://unix" host in the URL is a placeholder net/http requires; the actual connection goes to socketPath. The dialer is a
// per-call net.Dialer so the outer request's context cancellation propagates to the connect attempt.
//
// Proxy is intentionally left at its zero value (nil) so the transport never consults HTTP_PROXY/HTTPS_PROXY env vars. Unlike
// http.DefaultTransport (which sets Proxy=ProxyFromEnvironment), a Transport literal with Proxy unset bypasses all proxies, which
// is what we want for unix-socket dialing.
func unixSocketHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: unixSocketHTTPTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// defaultHTTPClient builds the http.Client PostDirect uses. Modest timeout so a hung server fails the test rather than wedging it.
func defaultHTTPClient() *http.Client { return &http.Client{Timeout: postDirectHTTPTimeout} }

// sleepCtx is a context-aware sleep: returns the context's error if it cancels before the duration elapses.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// buildPayload constructs the per-event-type payload object that the wire envelope embeds. The function picks the right field
// subset for each event_type and emits exactly that, dropping zero-valued optional fields via the per-type struct's json tags.
// Required-but-empty fields are NOT defaulted because the test author should see the resulting validation error from the server
// and fix their scenario rather than silently shipping a malformed event.
func buildPayload(ev Event) (json.RawMessage, error) {
	switch ev.Type {
	case "exec":
		return json.Marshal(struct {
			PID  int      `json:"pid"`
			PPID int      `json:"ppid"`
			Path string   `json:"path"`
			Args []string `json:"args"`
			CWD  string   `json:"cwd"`
			UID  int      `json:"uid"`
			GID  int      `json:"gid"`
		}{ev.PID, ev.PPID, ev.Path, ev.Args, ev.CWD, ev.UID, ev.GID})
	case "fork":
		return json.Marshal(struct {
			ChildPID  int `json:"child_pid"`
			ParentPID int `json:"parent_pid"`
		}{ev.ChildPID, ev.ParentPID})
	case "exit":
		out := struct {
			PID        int    `json:"pid"`
			ExitCode   int    `json:"exit_code"`
			ExitReason string `json:"exit_reason,omitempty"`
		}{ev.PID, ev.ExitCode, ev.ExitReason}
		return json.Marshal(out)
	case "open":
		return json.Marshal(struct {
			PID   int    `json:"pid"`
			Path  string `json:"path"`
			Flags int    `json:"flags"`
		}{ev.PID, ev.Path, ev.Flags})
	case "network_connect":
		out := struct {
			PID           int    `json:"pid"`
			Protocol      string `json:"protocol"`
			Direction     string `json:"direction"`
			LocalAddress  string `json:"local_address,omitempty"`
			LocalPort     int    `json:"local_port,omitempty"`
			RemoteAddress string `json:"remote_address"`
			RemotePort    int    `json:"remote_port"`
		}{ev.PID, ev.Protocol, ev.Direction, ev.LocalAddress, ev.LocalPort, ev.RemoteAddress, ev.RemotePort}
		return json.Marshal(out)
	case "dns_query":
		out := struct {
			PID               int      `json:"pid"`
			QueryName         string   `json:"query_name"`
			QueryType         string   `json:"query_type"`
			ResponseAddresses []string `json:"response_addresses,omitempty"`
			Protocol          string   `json:"protocol,omitempty"`
		}{ev.PID, ev.QueryName, ev.QueryType, ev.ResponseAddresses, ev.Protocol}
		return json.Marshal(out)
	case "snapshot_heartbeat":
		return json.Marshal(struct {
			PID int `json:"pid"`
		}{ev.PID})
	default:
		// knownEventTypes guarded the YAML loader, so reaching this is a bug in the library, not a user-input issue.
		return nil, fmt.Errorf("buildPayload: unhandled event_type %q", ev.Type)
	}
}
