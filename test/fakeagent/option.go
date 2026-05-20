package fakeagent

import (
	"crypto/rand"
	"encoding/hex"
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
// (e.g. 10.0 means a 1s scenario takes 100ms). Negative values panic at run-time.
func WithSpeed(multiplier float64) Option {
	return func(c *runConfig) { c.speedMultiplier = multiplier }
}

// WithBatchSize controls how many envelopes PostDirect bundles into a single /api/events POST. Default 100. Has no effect on
// FeedControlPlane, which posts one envelope per /event call by design (the headless binary's control plane mirrors the production
// receiver's one-event-at-a-time semantics).
func WithBatchSize(n int) Option { return func(c *runConfig) { c.batchSize = n } }

// WithIDGenerator overrides the function used to derive each envelope's event_id. The default produces a 32-hex-char random ID per
// envelope; tests pass a deterministic generator to make golden comparisons reproducible.
func WithIDGenerator(f func() string) Option { return func(c *runConfig) { c.idGenerator = f } }

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
