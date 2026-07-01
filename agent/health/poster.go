package health

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	defaultPostInterval = 60 * time.Second
	defaultDebounce     = 2 * time.Second
)

// TokenSource supplies the current host bearer token and the re-enroll trigger. enrollment.Provider satisfies it. The poster reads the
// token fresh on every post so it always uses the value the refresh loop most recently minted.
type TokenSource interface {
	Token() string
	OnUnauthorized(ctx context.Context)
}

// Options bundles the poster's dependencies. Interval and Debounce default when zero; NowNs defaults to the wall clock.
type Options struct {
	Registry     *Registry
	Client       *http.Client
	BaseURL      string
	Tokens       TokenSource
	AgentVersion string
	Interval     time.Duration
	Debounce     time.Duration
	Logger       *slog.Logger
	NowNs        func() int64
}

// Poster reports the registry's current health to POST /api/status: once at startup, again on any status transition (debounced), and on
// a periodic floor so the server's view refreshes even with no transitions. It is an idempotent snapshot channel, so a dropped post
// self-heals on the next one; the poster therefore does not retry a failed post itself.
type Poster struct {
	reg          *Registry
	client       *http.Client
	baseURL      string
	tokens       TokenSource
	agentVersion string
	interval     time.Duration
	debounce     time.Duration
	logger       *slog.Logger
	nowNs        func() int64
}

// NewPoster builds a Poster. Panics on a missing Registry, Client, or Tokens: those are wiring bugs, not runtime conditions.
func NewPoster(opts Options) *Poster {
	if opts.Registry == nil || opts.Client == nil || opts.Tokens == nil {
		panic("health.NewPoster: Registry, Client, and Tokens are required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = defaultPostInterval
	}
	debounce := opts.Debounce
	if debounce <= 0 {
		debounce = defaultDebounce
	}
	nowNs := opts.NowNs
	if nowNs == nil {
		nowNs = func() int64 { return time.Now().UnixNano() }
	}
	return &Poster{
		reg:          opts.Registry,
		client:       opts.Client,
		baseURL:      opts.BaseURL,
		tokens:       opts.Tokens,
		agentVersion: opts.AgentVersion,
		interval:     interval,
		debounce:     debounce,
		logger:       logger,
		nowNs:        nowNs,
	}
}

// Run posts on startup, then on each debounced transition and each periodic tick, until ctx is cancelled. Intended to run in its own
// goroutine alongside the agent's other background loops.
func (p *Poster) Run(ctx context.Context) {
	p.post(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.post(ctx)
		case <-p.reg.Changed():
			if !p.waitDebounce(ctx) {
				return
			}
			p.post(ctx)
		}
	}
}

// waitDebounce coalesces a burst of transitions after the first Changed signal: it waits `debounce`, resetting the timer on each further
// signal, so a rapid flap collapses into a single post. Returns false when ctx is cancelled.
func (p *Poster) waitDebounce(ctx context.Context) bool {
	timer := time.NewTimer(p.debounce)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-p.reg.Changed():
			// Restart the debounce window. On Go 1.23+ a stopped/reset timer never delivers a stale value, so no manual channel drain is
			// needed (and the old `if !Stop() { <-C }` drain can block); Stop then Reset is the current idiom.
			timer.Stop()
			timer.Reset(p.debounce)
		case <-timer.C:
			return true
		}
	}
}

// post builds and sends one snapshot. Failures are logged and dropped, not retried: the next tick or transition re-sends the current
// state, so a transient failure self-heals without the poster holding retry state.
func (p *Poster) post(ctx context.Context) {
	tok := p.tokens.Token()
	if tok == "" {
		// Pre-enrollment: no token yet. Skip rather than provoke a 401 -> re-enroll storm before the agent has enrolled.
		p.logger.DebugContext(ctx, "status check-in skipped: not enrolled yet")
		return
	}
	body, err := json.Marshal(report{
		AgentVersion: p.agentVersion,
		ReportedAtNs: p.nowNs(),
		Components:   p.reg.Snapshot(),
	})
	if err != nil {
		p.logger.ErrorContext(ctx, "status check-in marshal", "err", err)
		return
	}
	url := strings.TrimRight(p.baseURL, "/") + "/api/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		p.logger.ErrorContext(ctx, "status check-in request", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		p.logger.WarnContext(ctx, "status check-in send", "err", err)
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		p.logger.DebugContext(ctx, "status check-in ok", "status", resp.StatusCode)
	case resp.StatusCode == http.StatusUnauthorized:
		// The token is no longer valid; drive the same re-enroll path the other agent routes use.
		p.tokens.OnUnauthorized(ctx)
	default:
		p.logger.WarnContext(ctx, "status check-in rejected", "status", resp.StatusCode)
	}
}
