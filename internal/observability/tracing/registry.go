package tracing

import "sync"

// Tier classifies a span for head sampling. The zero value is TierFull, so any span whose route is not registered is sampled at
// 100%: absence from the noisy lists is what keeps the load-bearing flows safe by default.
type Tier int

const (
	// TierFull is the catch-all (zero value). Unregistered spans land here and are sampled at 100%: writes, admin mutations, enroll,
	// command delivery, and every span the registry does not explicitly downsample.
	TierFull Tier = iota

	// TierStandard is operator and UI read traffic: the dashboard GET endpoints. Moderate volume, moderate diagnostic value. Sampled
	// at the configured standard ratio.
	TierStandard

	// TierHighVolume is the agent data plane that dominates request volume without being individually interesting (event ingest, the
	// command poll, token refresh, enroll). Sampled at the configured high-volume ratio.
	TierHighVolume

	// TierDrop is liveness/health/version probe traffic: high volume, zero diagnostic value. Dropped unconditionally, and the drop
	// wins over the force-full override so a debug window does not flood the backend with probe spans.
	TierDrop
)

// Registry maps a span name ("METHOD /path", the format the HTTP span-name formatter emits) to a Tier. The server layer populates it
// at startup; the sampler reads it via Lookup on every span. A span name not present returns TierFull.
//
// Routes added after the sampler is constructed are picked up immediately: the sampler holds the *Registry and reads it live.
type Registry struct {
	mu     sync.RWMutex
	routes map[string]Tier
}

// NewRegistry returns an empty Registry. Routes are added via Register.
func NewRegistry() *Registry {
	return &Registry{routes: make(map[string]Tier)}
}

// Register classifies a method+path. Re-registering the same method+path overwrites the prior tier. The key is method+" "+path,
// matching the span name the otelhttp span-name formatter produces ("POST /api/events").
func (r *Registry) Register(method, path string, tier Tier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[method+" "+path] = tier
}

// Lookup returns the tier for a span name, or TierFull when the span name is not registered (the safe-by-default catch-all). Non-HTTP
// span names (cron, internal work) are simply absent and fall to TierFull.
func (r *Registry) Lookup(spanName string) Tier {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.routes[spanName]
}
