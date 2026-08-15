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
	// defaultBackoff is the base wait between attempts, scaled linearly by attempt number (1x, 2x, 3x). Spacing matters
	// because each attempt writes NetworkExtension preferences, which briefly disrupts the very flows the provider is
	// meant to capture.
	defaultBackoff = 30 * time.Second
)

// Remediator re-enables one capture provider. Injected so the controller's policy is testable without the host app; the
// darwin implementation runs the host-app subcommand, and non-darwin builds supply nil, which makes the controller inert.
type Remediator interface {
	Enable(ctx context.Context, provider string) error
}

// HealthSink is the slice of the agent's health registry the controller writes back to. Kept to the one method so the
// controller does not acquire the whole registry surface, and so tests can assert escalation without one.
type HealthSink interface {
	MarkSelfHealFailed(compType, message string)
}

// Escalation is what the controller reports when its repair budget for one provider is spent: the host is not capturing
// that telemetry and will not start on its own.
//
// Outcome carries WHICH of the two failure shapes was reached rather than a bare "it failed", because they point a
// responder at different things and the controller is the only place that can tell them apart (see remediate).
type Escalation struct {
	Provider string
	Attempts int
	Outcome  string
}

// The two shapes an exhausted budget can end in.
const (
	// OutcomeEnableFailed: the repair command itself kept failing, implicating the host app or the configuration daemon.
	OutcomeEnableFailed = "enable_failed"
	// OutcomeEnableIneffective: every repair reported success and the provider stayed stopped, so re-enabling is not what
	// this fault needs. This is the more alarming of the two, because the automation believes it is working.
	OutcomeEnableIneffective = "enable_ineffective"
)

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
	// OnEscalation is called exactly once per stop episode, at the moment the repair budget is spent. Optional; nil
	// disables it.
	//
	// It is a callback rather than an event emitter because this package deliberately owns policy and not wire format
	// (see the package comment): the caller decides that "the budget is spent" becomes a durable server-side event. It is
	// deliberately NOT wired through escalate(), which re-runs on every later report to re-assert level health state.
	// Health is idempotent under that; an event is an append, so emitting there would produce one event per liveness
	// report for as long as the provider stayed down.
	OnEscalation func(Escalation)
}

// Controller restores stopped capture providers. It observes the same liveness reports the health registry grades, so it
// acts on the extension's own account of what is running rather than on a second, possibly divergent, source of truth.
//
// Concurrency: Observe is called from the receiver loop's event callback and remediation runs on its own goroutine, so the
// per-provider state is mutex-guarded. Only one remediation runs at a time per provider.
type Controller struct {
	remediator   Remediator
	health       HealthSink
	component    string
	logger       *slog.Logger
	grace        time.Duration
	maxAttempts  int
	backoff      time.Duration
	now          func() time.Time
	onEscalation func(Escalation)

	mu    sync.Mutex
	state map[string]*providerState
}

// providerState is what the controller remembers about one provider between reports.
type providerState struct {
	// eligibleAt is the earliest time the next remediation may run. Set to stop-time + grace when the stop is first seen,
	// then to now + backoff after each attempt. It is a single explicit deadline rather than a stop timestamp the grace
	// window is re-applied to, because re-applying grace to a backed-off timestamp made the real gap between attempts
	// backoff + grace, which is neither what the constants say nor what anyone reading them would predict.
	eligibleAt time.Time
	// attempts counts remediations tried for the CURRENT stop. Reset when the provider is seen running again, so a host
	// that fails intermittently over a long period is retried each time rather than being written off permanently.
	attempts int
	// remediating guards against a second remediation being launched for a provider while one is in flight; reports keep
	// arriving during the several seconds an enable takes.
	remediating bool
	// escalation is the operator-facing diagnosis recorded when the budget was spent; empty means the budget remains. It is
	// retained rather than being a bare bool because it has to be RE-ASSERTED on every later report: the receiver loop calls
	// MarkProviders before Observe, and that overwrites the component's reason with provider_stopped. Without re-asserting,
	// self_heal_failed would survive for microseconds after the final attempt and the operator would never see that
	// automation had given up, which is the whole point of having a distinct reason.
	escalation string
}

// New builds a Controller. A nil Remediator disables remediation entirely, which is what non-darwin builds get.
func New(opts Options) *Controller {
	c := &Controller{
		remediator:   opts.Remediator,
		health:       opts.Health,
		component:    opts.Component,
		logger:       opts.Logger,
		grace:        opts.Grace,
		maxAttempts:  opts.MaxAttempts,
		backoff:      opts.Backoff,
		now:          opts.Now,
		onEscalation: opts.OnEscalation,
		state:        map[string]*providerState{},
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
	launched, attempts, reassert := c.plan(ctx, providers)
	// Both of these run OUTSIDE the controller's mutex: escalate takes the health registry's lock, and holding two locks in
	// an order nothing else guarantees is how deadlocks get built.
	for provider, detail := range reassert {
		c.escalate(provider, detail)
	}
	for _, name := range launched {
		go c.remediate(ctx, name, attempts[name])
	}
	return launched
}

// plan is the locked half of Observe: it advances the per-provider state and reports what the caller should do. Split out so
// the mutex is released before any call that reaches the health registry or spawns a remediation.
func (c *Controller) plan(ctx context.Context, providers map[string]string) (
	launched []string, attempts map[string]int, reassert map[string]string,
) {
	stopped := map[string]bool{}
	for _, p := range Remediable(providers) {
		stopped[p] = true
	}
	running := map[string]bool{}
	for name, state := range providers {
		if state == ProviderRunning {
			running[name] = true
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// ONLY an affirmative running report clears the state and restores the attempt budget. Absence is not recovery: a
	// provider is also absent when the operator disabled it, when nothing has started yet, and when parseProviderStatus
	// could not decode the payload and returned an empty map. Clearing on absence would hand a fresh budget to a provider
	// that alternates between stopped and any of those, so maxAttempts would stop bounding anything and the agent would
	// rewrite NetworkExtension preferences without limit. Each rewrite briefly disrupts the very flows the provider
	// captures, so that failure mode is sustained capture loss, not just log noise.
	for name, st := range c.state {
		if !running[name] {
			continue
		}
		c.logger.InfoContext(ctx, "capture provider is running again; clearing self-heal state",
			"provider", name, "attempts", st.attempts)
		delete(c.state, name)
	}

	now := c.now()
	attempts = map[string]int{}
	reassert = map[string]string{}
	for name := range stopped {
		st := c.state[name]
		if st == nil {
			// First report of this stop: nothing is eligible until the grace window passes, because a stop is routine
			// during an activation or upgrade cutover and usually clears on its own within seconds.
			c.state[name] = &providerState{eligibleAt: now.Add(c.grace)}
			c.logger.InfoContext(ctx, "capture provider stopped; starting self-heal grace window",
				"provider", name, "grace", c.grace)
			continue
		}
		if st.escalation != "" {
			// Budget spent. Re-assert the escalation the caller will publish, because MarkProviders already overwrote the
			// component's reason with provider_stopped moments ago.
			reassert[name] = st.escalation
			continue
		}
		if st.remediating || now.Before(st.eligibleAt) {
			continue
		}
		st.remediating = true
		st.attempts++
		attempts[name] = st.attempts
		launched = append(launched, name)
	}
	sort.Strings(launched)
	return launched, attempts, reassert
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
	// The budget bounds ATTEMPTS, not failures. An enable that returns success but does not actually bring the provider
	// back still burns one: the provider is still stopped in the next report, so a success-only path that skipped this
	// check would retry forever, rewriting NetworkExtension preferences indefinitely while the host stayed blind. That is
	// the unbounded repair loop this design exists to avoid, and it is reachable whenever the enable is accepted but
	// ineffective. Only a report showing the provider no longer stopped clears the state and restores the budget.
	exhausted := attempt >= c.maxAttempts
	var detail, outcome string
	if exhausted {
		// The two shapes need different diagnoses. "Every enable failed" points at the host app or the configuration
		// daemon; "every enable succeeded and it is still stopped" says re-enabling is simply not what this fault needs.
		if err == nil {
			detail = "was re-enabled " + strconv.Itoa(attempt) + " times but is still not capturing"
			outcome = OutcomeEnableIneffective
		} else {
			detail = "could not be automatically restored after " + strconv.Itoa(attempt) + " attempts"
			outcome = OutcomeEnableFailed
		}
		st.escalation = detail
	} else {
		// Space the next attempt by the backoff alone. The grace window is a property of the stop, not of each retry, so it
		// is deliberately NOT re-applied here.
		st.eligibleAt = c.now().Add(c.backoff * time.Duration(attempt))
	}
	c.mu.Unlock()

	switch {
	case err == nil && !exhausted:
		c.logger.InfoContext(ctx, "capture provider re-enabled; awaiting the extension's next report to confirm",
			"provider", provider, "attempt", attempt)
	case err == nil:
		c.logger.ErrorContext(ctx, "capture provider still stopped after every enable succeeded; operator action required",
			"provider", provider, "attempts", attempt)
	case !exhausted:
		c.logger.WarnContext(ctx, "could not re-enable capture provider; will retry",
			"provider", provider, "attempt", attempt, "max", c.maxAttempts, "err", err)
	default:
		c.logger.ErrorContext(ctx, "giving up on re-enabling capture provider; operator action required",
			"provider", provider, "attempts", attempt, "err", err)
	}
	if exhausted {
		c.escalate(provider, detail)
		// The EDGE, and the only place this fires. escalate() above runs again on every later report to re-assert health,
		// which is safe for level state and would be an event storm for anything append-only (issue #691).
		if c.onEscalation != nil {
			c.onEscalation(Escalation{Provider: provider, Attempts: attempt, Outcome: outcome})
		}
	}
}

// escalate publishes the operator-facing "automation gave up" state. Separate from the log lines because the two failure
// shapes (the enable kept failing, versus the enable kept succeeding without effect) need different diagnoses but the same
// health treatment.
func (c *Controller) escalate(provider, detail string) {
	if c.health == nil {
		return
	}
	c.health.MarkSelfHealFailed(c.component, provider+" "+detail+"; operator action required")
}
