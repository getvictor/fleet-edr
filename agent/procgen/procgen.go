// Package procgen tracks the live kernel process generation (pid -> pidversion) for the local host so the command executor can pin a
// kill_process command to the exact process generation the operator selected, refusing the kill when that PID has since been reused or
// re-exec'd (issue #627).
//
// macOS exposes pidversion (audit_token_to_pidversion) only on the audit token carried by an Endpoint Security event, never for an
// arbitrary running pid, and there is no pidfd-style reuse-proof handle. So the only way the agent can know a live pid's generation is to
// accumulate it from the exec/fork/exit event stream the extension already delivers. The registry is therefore a per-replica, in-memory
// cache that is safe to lose (ADR-0010): an empty or stale map degrades to today's pid-only kill. Verification only ever STRENGTHENS the
// behavior: a match or an unknown pid proceeds, and only a KNOWN generation mismatch is refused, so the registry can never refuse a kill
// that would previously have succeeded.
package procgen

import (
	"bytes"
	"encoding/json"
	"sync"
)

// Verdict is the result of checking a (pid, expected pidversion) against the live generation map.
type Verdict int

const (
	// VerdictUnknown means the pid is not currently tracked: never observed, observed-then-exited, or lost across an agent restart. The
	// caller should fall back to its default (pid-only) behavior rather than refuse, so verification only ever strengthens.
	VerdictUnknown Verdict = iota
	// VerdictMatch means the pid is live and its current generation equals the expected pidversion.
	VerdictMatch
	// VerdictMismatch means the pid is live but at a DIFFERENT generation than expected (PID reuse or re-exec): the caller MUST refuse.
	VerdictMismatch
)

// Registry is a concurrency-safe map of pid -> current pidversion for processes observed live on this host.
type Registry struct {
	mu  sync.RWMutex
	gen map[int]uint32
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{gen: make(map[int]uint32)}
}

// Check reports whether killing pid would target the generation identified by expected. A nil Registry reports VerdictUnknown so a
// disabled/absent registry degrades to pid-only behavior at the call site.
func (r *Registry) Check(pid int, expected uint32) Verdict {
	if r == nil {
		return VerdictUnknown
	}
	r.mu.RLock()
	cur, ok := r.gen[pid]
	r.mu.RUnlock()
	switch {
	case !ok:
		return VerdictUnknown
	case cur == expected:
		return VerdictMatch
	default:
		return VerdictMismatch
	}
}

// observe records that pid is live at generation pidversion (an exec or fork). A later exec on the same pid (a re-exec, which increments
// the kernel pidversion) overwrites the entry, so the map always holds the latest generation.
func (r *Registry) observe(pid int, pidversion uint32) {
	if pid <= 0 {
		return
	}
	r.mu.Lock()
	r.gen[pid] = pidversion
	r.mu.Unlock()
}

// forget removes pid from the map on exit, so a later Check of a now-freed pid returns VerdictUnknown (the caller then falls back to
// pid-only behavior) rather than a stale match.
func (r *Registry) forget(pid int) {
	r.mu.Lock()
	delete(r.gen, pid)
	r.mu.Unlock()
}

// Len returns the number of tracked pids. Observability/test aid. Nil-safe like the rest of the Registry API (a nil registry tracks
// nothing), so a caller holding a degraded/absent registry does not have to special-case it.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.gen)
}

// ObserveEventBytes parses one raw event envelope (the same JSON the extension delivers over XPC) and updates the map: an exec or fork
// records the process's generation, an exit removes it. Envelopes without a usable pidversion (the boot snapshot, or an agent predating
// the field) and event types other than exec/fork/exit are ignored. Malformed JSON is ignored so a bad event never breaks delivery. This
// is invoked on the XPC receive path BEFORE the lossy upload queue, so the map's fidelity tracks XPC delivery rather than the queue depth.
func (r *Registry) ObserveEventBytes(data []byte) {
	// Nil-safe: this runs off the GenerationSink interface, which can carry a typed-nil *Registry; degrade to a no-op rather than panic.
	if r == nil {
		return
	}
	// Fast path: the receive path sees every event, and network_connect / dns_query dominate volume, so skip the JSON parse unless the raw
	// bytes could be one of the three process-lifecycle events we track. A false positive (the literal appears in a path or domain) just
	// falls through to the full parse; there are no false negatives because a real exec/fork/exit always carries "event_type":"<kind>".
	if !bytes.Contains(data, []byte(`"exec"`)) && !bytes.Contains(data, []byte(`"fork"`)) && !bytes.Contains(data, []byte(`"exit"`)) {
		return
	}
	var env eventEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return
	}
	switch env.EventType {
	case "exec":
		if env.Payload.PIDVersion != nil {
			r.observe(env.Payload.PID, *env.Payload.PIDVersion)
		}
	case "fork":
		if env.Payload.PIDVersion != nil {
			r.observe(env.Payload.ChildPID, *env.Payload.PIDVersion)
		}
	case "exit":
		r.forget(env.Payload.PID)
	}
}

// eventEnvelope is the minimal projection of the event wire envelope (schema/events.json) the registry needs: the type plus the
// pid/child_pid/pidversion off the payload. exec carries pid + pidversion; fork carries child_pid + the child's pidversion; exit carries
// pid. Only these fields are decoded.
type eventEnvelope struct {
	EventType string `json:"event_type"`
	Payload   struct {
		PID        int     `json:"pid"`
		ChildPID   int     `json:"child_pid"`
		PIDVersion *uint32 `json:"pidversion"`
	} `json:"payload"`
}
