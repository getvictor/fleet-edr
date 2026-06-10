package fakeagent

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

// runConfig is the resolved set of knobs the envelope builder + feeders read at runtime. Defaults are filled in by newRunConfig;
// Option values applied via With* mutate the config before use.
type runConfig struct {
	startTime       time.Time
	hostIDOverride  string
	speedMultiplier float64
	batchSize       int
	idGenerator     func() string
	httpClient      *http.Client
}

// Option is the functional-option type for FeedControlPlane, PostDirect, and Envelopes. Use With* helpers to construct values.
type Option func(*runConfig)

// WithStartTime fixes the scenario's start instant. Every timeline event's wire timestamp_ns becomes startTime + at.nanoseconds.
// Default: time.Now() at call time, which is fine for live traffic but produces non-deterministic envelopes; tests should pass a
// fixed value so golden comparisons and event-id derivations stay stable across runs.
func WithStartTime(t time.Time) Option { return func(c *runConfig) { c.startTime = t } }

// WithHostID replaces the host id baked into the scenario's metadata. The scenario's host.id remains for log lines, but every
// emitted envelope's host_id field uses the override. Test code that wants N hosts from one scenario simply varies this.
func WithHostID(id string) Option { return func(c *runConfig) { c.hostIDOverride = id } }

// WithSpeed sets the playback speed. 0 (the default) fires every event immediately, ignoring the timeline's At offsets entirely;
// the wire timestamps still reflect At but the feeder doesn't sleep. 1.0 plays at real time. Higher values compress the timeline
// (e.g. 10.0 means a 1s scenario takes 100ms). Negative or zero values are treated as 0 (fire immediately).
func WithSpeed(multiplier float64) Option {
	return func(c *runConfig) { c.speedMultiplier = multiplier }
}

// WithBatchSize controls how many envelopes PostDirect bundles into a single /api/events POST. Default 100. Has no effect on
// FeedControlPlane, which posts one envelope per /event call by design (the headless binary's control plane mirrors the production
// receiver's one-event-at-a-time semantics). Panics on n <= 0 because PostDirect's `for start += cfg.batchSize` loop would either
// never advance (n=0, infinite loop) or run backwards (n<0). Neither is a recoverable state, and the panic gives the test author
// a clear stack to the misconfiguration rather than a hanging or unbounded test run.
func WithBatchSize(n int) Option {
	if n <= 0 {
		panic("fakeagent: WithBatchSize requires n > 0")
	}
	return func(c *runConfig) { c.batchSize = n }
}

// WithIDGenerator overrides the function used to derive each envelope's event_id. The default produces a 32-hex-char random ID per
// envelope; tests pass a deterministic generator to make golden comparisons reproducible. Panics on a nil function so the failure
// surfaces at the WithIDGenerator(nil) call site rather than later in Envelopes when cfg.idGenerator() dereferences nil.
func WithIDGenerator(f func() string) Option {
	if f == nil {
		panic("fakeagent: WithIDGenerator requires a non-nil function")
	}
	return func(c *runConfig) { c.idGenerator = f }
}

// WithHTTPClient overrides the *http.Client PostDirect uses for POSTs to /api/events. The default builds a client with the
// project's postDirectHTTPTimeout and stock TLS verification; callers that need shared connection pools (e.g. fan-out load
// generators) or a custom TLS config (e.g. dev:server's mkcert-signed cert when the system trust store has not been primed)
// pass their own client here. Has no effect on FeedControlPlane, which dials a unix socket. Panics on a nil client so the
// failure surfaces at the call site rather than later in PostDirect when client.Do() dereferences nil.
func WithHTTPClient(c *http.Client) Option {
	if c == nil {
		panic("fakeagent: WithHTTPClient requires a non-nil client")
	}
	return func(cfg *runConfig) { cfg.httpClient = c }
}

// newRunConfig builds the resolved config, applies any options, then returns it.
func newRunConfig(opts []Option) *runConfig {
	c := &runConfig{
		startTime:       time.Now(),
		speedMultiplier: 0,
		batchSize:       100,
		idGenerator:     randomEventID,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// randomEventID returns a 32-character lower-hex random identifier. Stable, dependency-free, sufficient for collision-free
// scenario runs at the volumes this library is designed for (single-digit thousands of events per run).
func randomEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read on a properly configured OS does not fail; the panic here is defensive and would surface as a test
		// failure rather than producing duplicated event_ids that mask a real bug downstream.
		panic("fakeagent: crypto/rand.Read: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
