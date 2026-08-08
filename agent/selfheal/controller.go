package selfheal

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	// defaultGrace is how long a provider must stay stopped before it is remediated. A stop is routine during an activation
	// or an upgrade cutover and usually clears on its own within seconds, so remediating instantly would race those
	// recoveries and write configuration nobody needed.
	defaultGrace = 30 * time.Second
	// defaultMaxAttempts bounds retries for one stop. Past this the fault is not the kind re-enabling fixes, and continuing
	// would rewrite system configuration forever while hiding the real problem behind apparent recovery.
	defaultMaxAttempts = 3
	// defaultBackoff is the wait after a failed attempt, doubled per attempt. Spacing matters because each attempt writes
	// NetworkExtension preferences, which briefly disrupts the very flows the provider is meant to capture.
	defaultBackoff = 30 * time.Second
)

// Remediator re-enables one capture provider. Injected so the controller's policy is testable without the host app; the
// darwin implementation runs the host-app subcommand, and non-darwin builds get a stub that reports it is unsupported.
type Remediator interface {
	Enable(ctx context.Context, provider string) error
}

// HealthSink is the slice of the agent's health registry the controller writes back to. Kept to the one method so the
// controller does not acquire the whole registry surface, and so tests can assert escalation without one.
type HealthSink interface {
	MarkSelfHealFailed(compType, message string)
}

// Options bundles the controller's dependencies. Zero values for the tunables take the package defaults.
type Options struct {
	Remediator  Remediator
	Health      HealthSink
	Component   string
	Logger      *slog.Logger
	Grace       time.Duration
	MaxAttempts int
	Backoff     time.Duration
	// Now is the clock, injected so tests drive the grace window and backoff without sleeping. It is called from the
	// remediation goroutine as well as from Observe, so an injected clock MUST be safe for concurrent use.
	Now func() time.Time
}

// Controller restores stopped capture providers. It observes the same liveness reports the health registry grades, so it
// acts on the extension's own account of what is running rather than on a second, possibly divergent, source of truth.
//
// Concurrency: Observe is called from the receiver loop's event callback and remediation runs on its own goroutine, so the
// per-provider state is mutex-guarded. Only one remediation runs at a time per provider.
type Controller struct {
	remediator  Remediator
	health      HealthSink
	component   string
	logger      *slog.Logger
	grace       time.Duration
	maxAttempts int
	backoff     time.Duration
	now         func() time.Time

	mu    sync.Mutex
	state map[string]*providerState
}

// providerState is what the controller remembers about one provider between reports.
type providerState struct {
	// stoppedSince is when this provider was first reported stopped in the current stop. Zero means it is not stopped.
	stoppedSince time.Time
	// attempts counts remediations tried for the CURRENT stop. Reset when the provider is seen running again, so a host
	// that fails intermittently over a long period is retried each time rather than being written off permanently.
	attempts int
	// remediating guards against a second remediation being launched for a provider while one is in flight; reports keep
	// arriving during the several seconds an enable takes.
	remediating bool
	// exhausted records that the budget for the current stop is spent, so repeated reports do not re-escalate or re-log.
	exhausted bool
}

// New builds a Controller. A nil Remediator disables remediation entirely, which is what non-darwin builds get.
func New(opts Options) *Controller {
	c := &Controller{
		remediator:  opts.Remediator,
		health:      opts.Health,
		component:   opts.Component,
		logger:      opts.Logger,
		grace:       opts.Grace,
		maxAttempts: opts.MaxAttempts,
		backoff:     opts.Backoff,
		now:         opts.Now,
		state:       map[string]*providerState{},
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	if c.grace <= 0 {
		c.grace = defaultGrace
	}
	if c.maxAttempts <= 0 {
		c.maxAttempts = defaultMaxAttempts
	}
	if c.backoff <= 0 {
		c.backoff = defaultBackoff
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c
}

// Observe takes a provider-liveness report and starts, continues or cancels remediation as it implies. It is called on
// every report, which the extension re-publishes on each agent handshake as well as on every transition, so this is the
// level-triggered view rather than an edge.
//
// Returns the providers for which a remediation was launched, so callers (and tests) can assert on the decision without
// waiting for the goroutines.
func (c *Controller) Observe(ctx context.Context, providers map[string]string) []string {
	if c.remediator == nil {
		return nil
	}
	stopped := map[string]bool{}
	for _, p := range Remediable(providers) {
		stopped[p] = true
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Any provider NOT reported stopped is either running or deliberately absent. Both mean there is nothing to fix, so
	// clear its state: that is what resets the attempt budget after a successful heal.
	for name, st := range c.state {
		if stopped[name] {
			continue
		}
		if st.attempts > 0 || !st.stoppedSince.IsZero() {
			c.logger.InfoContext(ctx, "capture provider no longer stopped; clearing self-heal state",
				"provider", name, "attempts", st.attempts)
		}
		delete(c.state, name)
	}

	now := c.now()
	var launched []string
	for name := range stopped {
		st := c.state[name]
		if st == nil {
			st = &providerState{stoppedSince: now}
			c.state[name] = st
			c.logger.InfoContext(ctx, "capture provider stopped; starting self-heal grace window",
				"provider", name, "grace", c.grace)
			continue
		}
		if st.remediating || st.exhausted {
			continue
		}
		if now.Sub(st.stoppedSince) < c.grace {
			continue
		}
		st.remediating = true
		st.attempts++
		attempt := st.attempts
		launched = append(launched, name)
		go c.remediate(ctx, name, attempt)
	}
	sort.Strings(launched)
	return launched
}

// remediate runs one enable attempt and records the outcome. It deliberately does NOT verify the provider came back: the
// extension's next liveness report is the authority on that, and treating our own exit code as proof would let a
// successful-but-ineffective enable clear the state.
func (c *Controller) remediate(ctx context.Context, provider string, attempt int) {
	c.logger.InfoContext(ctx, "restoring stopped capture provider", "provider", provider, "attempt", attempt, "max", c.maxAttempts)
	err := c.remediator.Enable(ctx, provider)

	c.mu.Lock()
	st := c.state[provider]
	if st == nil {
		// The provider was reported running (or absent) while this attempt was in flight, so its state was cleared. The
		// heal is moot either way; do not resurrect the entry.
		c.mu.Unlock()
		return
	}
	st.remediating = false
	if err == nil {
		// Push the next eligible attempt out by the backoff even on success, so that if the provider is still stopped in
		// the next report (the enable did not take) we do not immediately retry.
		st.stoppedSince = c.now().Add(c.backoff * time.Duration(attempt))
		c.mu.Unlock()
		c.logger.InfoContext(ctx, "capture provider re-enabled; awaiting the extension's next report to confirm",
			"provider", provider, "attempt", attempt)
		return
	}
	exhausted := attempt >= c.maxAttempts
	st.exhausted = exhausted
	if !exhausted {
		st.stoppedSince = c.now().Add(c.backoff * time.Duration(attempt))
	}
	c.mu.Unlock()

	if !exhausted {
		c.logger.WarnContext(ctx, "could not re-enable capture provider; will retry",
			"provider", provider, "attempt", attempt, "max", c.maxAttempts, "err", err)
		return
	}
	c.logger.ErrorContext(ctx, "giving up on re-enabling capture provider; operator action required",
		"provider", provider, "attempts", attempt, "err", err)
	if c.health != nil {
		c.health.MarkSelfHealFailed(c.component,
			"could not automatically restore "+provider+" after "+strconv.Itoa(attempt)+" attempts; operator action required")
	}
}
