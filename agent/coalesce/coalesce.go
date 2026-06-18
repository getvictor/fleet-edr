// Package coalesce reduces repetitive network_connect and dns_query telemetry before it is enqueued for upload (issue #408). The
// extension emits one event per socket flow and per DNS query (observation-only capture is a hard requirement), but a process that
// reconnects to the same destination 5-tuple repeatedly, or resolves the same name over and over, produces near-identical rows that
// dominate the events table for little forensic value. The Coalescer buffers these two event types for a bounded window and
// collapses events that share an identity key into one representative event plus an occurrence count, preserving the detection-
// relevant signal: the earliest timestamp (so a downstream correlation window measured backward from a later event is never
// shortened), an occurrence count and the latest timestamp (so the span is recoverable), and for DNS the union of every resolved
// address (so a later connection to any resolved IP still correlates). Every other event type is passed straight through with no
// added latency.
package coalesce

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// EnqueueFunc is the sink a coalesced (or passed-through) event is written to. It matches queue.Queue.Enqueue.
type EnqueueFunc func(ctx context.Context, eventJSON []byte) error

const (
	typeNetworkConnect = "network_connect"
	typeDNSQuery       = "dns_query"
)

// Coalescer buffers network_connect / dns_query events and flushes coalesced representatives on a window ticker. It is safe for
// concurrent Handle calls. A window of zero disables buffering entirely (every event passes straight through), restoring the
// pre-#408 per-occurrence behaviour.
type Coalescer struct {
	window     time.Duration
	maxEntries int
	enqueue    EnqueueFunc
	logger     *slog.Logger

	mu  sync.Mutex
	buf map[string]*entry
}

// defaultMaxEntries bounds the number of distinct identity keys buffered within one window. A host that touches many distinct
// destinations in a single window (a port scan, a crawler) would otherwise grow the buffer without bound between flushes; on reaching
// the cap the buffer is flushed early (lossless: every representative is enqueued, just sooner) rather than dropped. Mirrors the
// extension's pendingSendCap and the agent queue cap. 10k entries at a few hundred bytes each caps the buffer near a few MB.
const defaultMaxEntries = 10_000

// entry is one accumulating representative, keyed by identity. raw is the first-arriving event's exact bytes, returned verbatim
// when the entry never coalesced (count == 1) so a singleton is byte-identical to the un-coalesced path.
type entry struct {
	raw       []byte
	eventID   string
	hostID    string
	eventType string
	firstTSNs int64
	lastTSNs  int64
	count     int
	payload   map[string]json.RawMessage
	dnsAddrs  map[string]struct{} // union of response_addresses for DNS; nil for network_connect
}

// New returns a Coalescer that writes to enqueue. A non-positive window disables coalescing (Handle becomes a direct passthrough);
// callers can wire it unconditionally and let the window decide.
func New(window time.Duration, enqueue EnqueueFunc, logger *slog.Logger) *Coalescer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Coalescer{
		window:     window,
		maxEntries: defaultMaxEntries,
		enqueue:    enqueue,
		logger:     logger,
		buf:        make(map[string]*entry),
	}
}

// Enabled reports whether coalescing is active (a positive window). When false, Handle is a direct passthrough and Run is a no-op
// wait, so callers may skip starting the flush goroutine.
func (c *Coalescer) Enabled() bool { return c.window > 0 }

// Handle either buffers a coalescable event or enqueues it immediately. network_connect and dns_query are buffered (when enabled)
// and merged by identity key; every other event type, and anything that fails to parse, is enqueued unchanged so coalescing can
// never drop or corrupt a non-target event.
func (c *Coalescer) Handle(ctx context.Context, data []byte) error {
	if !c.Enabled() {
		return c.enqueue(ctx, data)
	}
	// Decode only the envelope headers first, keeping payload as raw bytes: a non-target event (exec/fork/exit/heartbeat/...) is
	// passed straight through without ever parsing its payload, so coalescing adds no decode cost to the events that dominate the
	// stream.
	var hdr struct {
		EventID     string          `json:"event_id"`
		HostID      string          `json:"host_id"`
		TimestampNs int64           `json:"timestamp_ns"`
		EventType   string          `json:"event_type"`
		Payload     json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(data, &hdr); err != nil {
		// Unparseable here means malformed upstream; let the normal path handle it rather than swallow it in the buffer.
		return c.enqueue(ctx, data)
	}
	if hdr.EventType != typeNetworkConnect && hdr.EventType != typeDNSQuery {
		return c.enqueue(ctx, data)
	}
	// Only the two coalescable types reach here, so the payload-map decode runs only when its fields are actually needed.
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(hdr.Payload, &payload); err != nil {
		return c.enqueue(ctx, data) // malformed target payload: pass through unchanged rather than buffer it
	}

	key := identityKey(hdr.EventType, payload)

	var overflow map[string]*entry
	c.mu.Lock()
	e, ok := c.buf[key]
	if !ok {
		// New identity key. Bound the buffer: if it is already at the cap, flush what we have first (lossless early flush) so a
		// host touching many distinct destinations in one window can't grow it without bound. The drained batch is enqueued after
		// the lock is released, since enqueue does I/O.
		if len(c.buf) >= c.maxEntries {
			overflow = c.drainLocked()
		}
		e = &entry{
			raw:       append([]byte(nil), data...), // copy only on first occurrence; the caller may reuse the slice
			eventID:   hdr.EventID,
			hostID:    hdr.HostID,
			eventType: hdr.EventType,
			firstTSNs: hdr.TimestampNs,
			lastTSNs:  hdr.TimestampNs,
			payload:   payload,
		}
		if hdr.EventType == typeDNSQuery {
			e.dnsAddrs = make(map[string]struct{})
		}
		c.buf[key] = e
	}
	e.count++
	if hdr.TimestampNs < e.firstTSNs {
		e.firstTSNs = hdr.TimestampNs
	}
	if hdr.TimestampNs > e.lastTSNs {
		e.lastTSNs = hdr.TimestampNs
	}
	if e.dnsAddrs != nil {
		for _, a := range responseAddresses(payload) {
			e.dnsAddrs[a] = struct{}{}
		}
	}
	c.mu.Unlock()

	c.emit(ctx, overflow)
	return nil
}

// Run drives the flush ticker until ctx is cancelled, then performs a final flush so a clean shutdown loses no buffered
// representatives. When coalescing is disabled it just blocks until ctx is done (nothing is ever buffered).
func (c *Coalescer) Run(ctx context.Context) {
	if !c.Enabled() {
		<-ctx.Done()
		return
	}
	ticker := time.NewTicker(c.window)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Detach from the cancelled ctx so the final enqueue can still reach the (still-open) queue. Idempotent with the
			// synchronous Flush the shutdown path calls before closing the queue: whichever runs first drains the buffer, the
			// other finds it empty.
			c.Flush(context.WithoutCancel(ctx))
			return
		case <-ticker.C:
			c.Flush(ctx)
		}
	}
}

// Flush drains the buffer under a lock-swap and enqueues each representative outside the lock (Enqueue does I/O). Exported so the
// agent shutdown path can drain buffered representatives into the queue before the queue is drained-and-closed; safe to call
// concurrently with Run's own flushes (the lock-swap guarantees each buffered entry is emitted at most once).
func (c *Coalescer) Flush(ctx context.Context) {
	c.mu.Lock()
	batch := c.drainLocked()
	c.mu.Unlock()
	c.emit(ctx, batch)
}

// drainLocked swaps out the current buffer and returns it, leaving a fresh empty buffer behind. The caller MUST hold c.mu. Shared
// by Flush and the cap-overflow path in Handle so the buffer is reset under the same lock that guards it.
func (c *Coalescer) drainLocked() map[string]*entry {
	if len(c.buf) == 0 {
		return nil
	}
	batch := c.buf
	c.buf = make(map[string]*entry)
	return batch
}

// emit marshals each representative and enqueues it, outside any lock (enqueue does I/O). A nil/empty batch is a no-op.
func (c *Coalescer) emit(ctx context.Context, batch map[string]*entry) {
	for _, e := range batch {
		data, err := e.marshal()
		if err != nil {
			c.logger.WarnContext(ctx, "coalesce marshal", "event_type", e.eventType, "err", err)
			continue
		}
		if err := c.enqueue(ctx, data); err != nil {
			c.logger.WarnContext(ctx, "coalesce enqueue", "event_type", e.eventType, "err", err)
		}
	}
}

// marshal renders the representative. A singleton (count == 1) is returned as its original bytes, byte-identical to the
// un-coalesced path. A coalesced entry patches its payload in place: coalesced_count, last_timestamp_ns, and (for DNS) the unioned
// response_addresses. The patch uses the first event's payload map so every other field is preserved exactly.
func (e *entry) marshal() ([]byte, error) {
	if e.count <= 1 {
		return e.raw, nil
	}
	payload := e.payload
	if payload == nil {
		payload = map[string]json.RawMessage{}
	}
	countJSON, _ := json.Marshal(e.count)
	payload["coalesced_count"] = countJSON
	lastJSON, _ := json.Marshal(e.lastTSNs)
	payload["last_timestamp_ns"] = lastJSON
	if e.dnsAddrs != nil {
		addrs := make([]string, 0, len(e.dnsAddrs))
		for a := range e.dnsAddrs {
			addrs = append(addrs, a)
		}
		sort.Strings(addrs) // deterministic ordering independent of map iteration / arrival order
		addrsJSON, err := json.Marshal(addrs)
		if err != nil {
			return nil, err
		}
		payload["response_addresses"] = addrsJSON
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	env := struct {
		EventID     string          `json:"event_id"`
		HostID      string          `json:"host_id"`
		TimestampNs int64           `json:"timestamp_ns"`
		EventType   string          `json:"event_type"`
		Payload     json.RawMessage `json:"payload"`
	}{
		EventID:     e.eventID,
		HostID:      e.hostID,
		TimestampNs: e.firstTSNs, // earliest occurrence
		EventType:   e.eventType,
		Payload:     payloadJSON,
	}
	return json.Marshal(env)
}

// identityKey builds the coalescing key for a target event. network_connect collapses on the 5-tuple plus pid/pidversion;
// dns_query collapses on pid/pidversion/query_name/query_type (which also merges a query with its follow-on response). pidversion
// is part of the key so a recycled PID with a new generation does not merge into the prior one; its absence is encoded distinctly
// from a present zero.
func identityKey(eventType string, payload map[string]json.RawMessage) string {
	get := func(k string) string {
		if v, ok := payload[k]; ok {
			return string(v)
		}
		return "\x00" // distinct from any present value, including JSON null
	}
	switch eventType {
	case typeNetworkConnect:
		return "nc|" + get("pid") + "|" + get("pidversion") + "|" + get("protocol") + "|" +
			get("direction") + "|" + get("remote_address") + "|" + get("remote_port")
	case typeDNSQuery:
		return "dns|" + get("pid") + "|" + get("pidversion") + "|" + get("query_name") + "|" + get("query_type")
	default:
		return eventType
	}
}

// responseAddresses decodes the dns_query response_addresses array, tolerating absence / null / malformed (returns nil).
func responseAddresses(payload map[string]json.RawMessage) []string {
	raw, ok := payload["response_addresses"]
	if !ok {
		return nil
	}
	var addrs []string
	if err := json.Unmarshal(raw, &addrs); err != nil {
		return nil
	}
	return addrs
}
