package coalesce

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// sink is a thread-safe EnqueueFunc capture. Run flushes from its own goroutine, so the slice must be locked.
type sink struct {
	mu  sync.Mutex
	got [][]byte
}

func (s *sink) enqueue(_ context.Context, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, append([]byte(nil), data...))
	return nil
}

func (s *sink) events() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.got))
	copy(out, s.got)
	return out
}

type parsed struct {
	EventID     string                     `json:"event_id"`
	HostID      string                     `json:"host_id"`
	TimestampNs int64                      `json:"timestamp_ns"`
	EventType   string                     `json:"event_type"`
	Payload     map[string]json.RawMessage `json:"payload"`
}

// testingT is satisfied by both *testing.T and *rapid.T so the decode helpers work in example-based and property tests alike.
type testingT interface {
	require.TestingT
	Helper()
}

func decode(t testingT, data []byte) parsed {
	t.Helper()
	var p parsed
	require.NoError(t, json.Unmarshal(data, &p))
	return p
}

func intField(t testingT, p parsed, key string) (int64, bool) {
	t.Helper()
	raw, ok := p.Payload[key]
	if !ok {
		return 0, false
	}
	var v int64
	require.NoError(t, json.Unmarshal(raw, &v))
	return v, true
}

func strSlice(t testingT, p parsed, key string) []string {
	t.Helper()
	raw, ok := p.Payload[key]
	if !ok {
		return nil
	}
	var v []string
	require.NoError(t, json.Unmarshal(raw, &v))
	return v
}

// spec:agent-event-queue/pre-enqueue-coalescing-of-repetitive-network-and-dns-telemetry/non-network-events-are-never-delayed-by-coalescing
func TestCoalescer_NonNetworkPassesThroughImmediately(t *testing.T) {
	t.Parallel()
	s := &sink{}
	c := New(time.Minute, s.enqueue, nil)
	raw := []byte(`{"event_id":"e1","host_id":"h","timestamp_ns":5,"event_type":"exec","payload":{"pid":1}}`)
	require.NoError(t, c.Handle(context.Background(), raw))

	got := s.events()
	require.Len(t, got, 1, "non-target event is enqueued immediately, not buffered")
	assert.JSONEq(t, string(raw), string(got[0]))
	assert.Equal(t, string(raw), string(got[0]), "non-target event must be byte-identical")
}

// spec:agent-event-queue/pre-enqueue-coalescing-of-repetitive-network-and-dns-telemetry/repeated-identical-connections-collapse-to-one-representative
func TestCoalescer_MergesIdenticalConnections(t *testing.T) {
	t.Parallel()
	s := &sink{}
	c := New(time.Minute, s.enqueue, nil)
	for i, ts := range []int64{30, 10, 20} { // out of order on purpose: earliest must win
		ev := mkConnect(t, "nc-"+string(rune('a'+i)), ts, 42, "tcp", "outbound", "1.2.3.4", 443, nil)
		require.NoError(t, c.Handle(context.Background(), ev))
	}
	assert.Empty(t, s.events(), "buffered, nothing enqueued until flush")

	c.Flush(context.Background())
	got := s.events()
	require.Len(t, got, 1, "three identical 5-tuples collapse to one representative")
	p := decode(t, got[0])
	assert.Equal(t, int64(10), p.TimestampNs, "envelope timestamp is the earliest occurrence")
	count, ok := intField(t, p, "coalesced_count")
	require.True(t, ok)
	assert.Equal(t, int64(3), count)
	last, ok := intField(t, p, "last_timestamp_ns")
	require.True(t, ok)
	assert.Equal(t, int64(30), last)
}

func TestCoalescer_DistinctTuplesDoNotMerge(t *testing.T) {
	t.Parallel()
	s := &sink{}
	c := New(time.Minute, s.enqueue, nil)
	require.NoError(t, c.Handle(context.Background(), mkConnect(t, "a", 1, 42, "tcp", "outbound", "1.2.3.4", 443, nil)))
	require.NoError(t, c.Handle(context.Background(), mkConnect(t, "b", 2, 42, "tcp", "outbound", "1.2.3.4", 8080, nil))) // diff port
	require.NoError(t, c.Handle(context.Background(), mkConnect(t, "c", 3, 99, "tcp", "outbound", "1.2.3.4", 443, nil)))  // diff pid
	c.Flush(context.Background())
	assert.Len(t, s.events(), 3, "different identity keys stay separate")
}

func TestCoalescer_PIDVersionDistinguishesKeys(t *testing.T) {
	t.Parallel()
	s := &sink{}
	c := New(time.Minute, s.enqueue, nil)
	v1, v2 := 7, 8
	require.NoError(t, c.Handle(context.Background(), mkConnect(t, "a", 1, 42, "tcp", "outbound", "1.2.3.4", 443, &v1)))
	require.NoError(t, c.Handle(context.Background(), mkConnect(t, "b", 2, 42, "tcp", "outbound", "1.2.3.4", 443, &v2)))
	c.Flush(context.Background())
	assert.Len(t, s.events(), 2, "a recycled PID with a new generation must not merge into the prior one")
}

// spec:agent-event-queue/pre-enqueue-coalescing-of-repetitive-network-and-dns-telemetry/a-dns-query-and-its-response-merge-preserving-all-answers
func TestCoalescer_DNSQueryAndResponseMerge(t *testing.T) {
	t.Parallel()
	s := &sink{}
	c := New(time.Minute, s.enqueue, nil)
	// query (no answers) then its follow-on response (two answers): same key, merge, union the answers.
	require.NoError(t, c.Handle(context.Background(), mkDNS(t, "q", 100, 42, "evil.example", "A", nil)))
	require.NoError(t, c.Handle(context.Background(), mkDNS(t, "r", 110, 42, "evil.example", "A", []string{"9.9.9.9", "8.8.8.8"})))
	c.Flush(context.Background())

	got := s.events()
	require.Len(t, got, 1)
	p := decode(t, got[0])
	assert.Equal(t, int64(100), p.TimestampNs, "earliest (the query) wins")
	count, _ := intField(t, p, "coalesced_count")
	assert.Equal(t, int64(2), count)
	addrs := strSlice(t, p, "response_addresses")
	assert.ElementsMatch(t, []string{"8.8.8.8", "9.9.9.9"}, addrs, "answers are the union, sorted deterministically")
	assert.Equal(t, []string{"8.8.8.8", "9.9.9.9"}, addrs, "union is sorted for determinism")
}

func TestCoalescer_SingletonIsByteIdentical(t *testing.T) {
	t.Parallel()
	s := &sink{}
	c := New(time.Minute, s.enqueue, nil)
	ev := mkConnect(t, "solo", 5, 42, "tcp", "outbound", "1.2.3.4", 443, nil)
	require.NoError(t, c.Handle(context.Background(), ev))
	c.Flush(context.Background())
	got := s.events()
	require.Len(t, got, 1)
	assert.Equal(t, string(ev), string(got[0]), "a single occurrence is emitted unchanged, with no coalesced_count added")
}

// spec:agent-event-queue/pre-enqueue-coalescing-of-repetitive-network-and-dns-telemetry/a-zero-window-disables-coalescing
func TestCoalescer_WindowZeroIsPassthrough(t *testing.T) {
	t.Parallel()
	s := &sink{}
	c := New(0, s.enqueue, nil)
	assert.False(t, c.Enabled())
	ev := mkConnect(t, "x", 5, 42, "tcp", "outbound", "1.2.3.4", 443, nil)
	require.NoError(t, c.Handle(context.Background(), ev))
	got := s.events()
	require.Len(t, got, 1, "with coalescing disabled the event is enqueued immediately")
	assert.Equal(t, string(ev), string(got[0]), "and unchanged")
}

// spec:agent-event-queue/pre-enqueue-coalescing-of-repetitive-network-and-dns-telemetry/buffered-representatives-are-flushed-on-shutdown
func TestCoalescer_FlushesOnShutdown(t *testing.T) {
	t.Parallel()
	s := &sink{}
	c := New(time.Hour, s.enqueue, nil) // window long enough that only the shutdown flush can emit
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()

	for i, ts := range []int64{1, 2} {
		require.NoError(t, c.Handle(ctx, mkConnect(t, "s"+string(rune('a'+i)), ts, 42, "tcp", "outbound", "1.2.3.4", 443, nil)))
	}
	assert.Empty(t, s.events(), "nothing emitted before shutdown")

	cancel()
	<-done // Run performs the final flush before returning
	got := s.events()
	require.Len(t, got, 1, "the buffered representative is flushed on shutdown")
	count, _ := intField(t, decode(t, got[0]), "coalesced_count")
	assert.Equal(t, int64(2), count)
}

// TestCoalescer_PropertyConnectionMerge: for any non-empty sequence of network_connect events sharing one identity key, the single
// representative carries the earliest timestamp, a count equal to the number of inputs, and the latest timestamp.
func TestCoalescer_PropertyConnectionMerge(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		timestamps := rapid.SliceOfN(rapid.Int64Range(1, 1_000_000), 1, 50).Draw(rt, "timestamps")
		s := &sink{}
		c := New(time.Minute, s.enqueue, nil)
		minTS, maxTS := timestamps[0], timestamps[0]
		for i, ts := range timestamps {
			if ts < minTS {
				minTS = ts
			}
			if ts > maxTS {
				maxTS = ts
			}
			require.NoError(rt, c.Handle(context.Background(), mkConnect(rt, "e"+string(rune(i)), ts, 42, "tcp", "outbound", "1.2.3.4", 443, nil)))
		}
		c.Flush(context.Background())
		got := s.events()
		require.Len(rt, got, 1, "one identity key yields exactly one representative")
		p := decode(rt, got[0])
		assert.Equal(rt, minTS, p.TimestampNs, "earliest timestamp preserved")
		if len(timestamps) > 1 {
			count, _ := intField(rt, p, "coalesced_count")
			assert.Equal(rt, int64(len(timestamps)), count)
			last, _ := intField(rt, p, "last_timestamp_ns")
			assert.Equal(rt, maxTS, last)
		}
	})
}

// TestCoalescer_PropertyDNSAddressUnion: for any sequence of dns_query events sharing one key, the representative's
// response_addresses equals the set union of every input's answers.
func TestCoalescer_PropertyDNSAddressUnion(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		addrPool := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "2.2.2.2", "::1"}
		batches := rapid.SliceOfN(
			rapid.SliceOf(rapid.SampledFrom(addrPool)),
			1, 20,
		).Draw(rt, "answerBatches")
		s := &sink{}
		c := New(time.Minute, s.enqueue, nil)
		want := map[string]struct{}{}
		for i, answers := range batches {
			for _, a := range answers {
				want[a] = struct{}{}
			}
			require.NoError(rt, c.Handle(context.Background(), mkDNS(rt, "d"+string(rune(i)), int64(i+1), 42, "host.example", "A", answers)))
		}
		c.Flush(context.Background())
		got := s.events()
		require.Len(rt, got, 1)
		// Compare as SETS: a single-occurrence event is passed through byte-identical and may retain duplicate addresses from that
		// one event, while a merged (count>1) representative dedups. The invariant either way is that the address SET equals the
		// union of every input's answers.
		gotSet := map[string]struct{}{}
		for _, a := range strSlice(rt, decode(rt, got[0]), "response_addresses") {
			gotSet[a] = struct{}{}
		}
		assert.Equal(rt, want, gotSet, "address set equals the union of all answers")
	})
}

// TestCoalescer_BufferCapEarlyFlush pins the bounded-buffer guard: when distinct identity keys reach the cap, the buffer is flushed
// early (lossless) instead of growing without bound, so a host touching many distinct destinations in one window can't balloon
// agent memory. Uses a long window so only the cap, never the ticker, can trigger emission.
func TestCoalescer_BufferCapEarlyFlush(t *testing.T) {
	t.Parallel()
	s := &sink{}
	c := New(time.Hour, s.enqueue, nil)
	c.maxEntries = 2 // white-box: shrink the cap so the test doesn't have to push 10k keys

	// Three distinct 5-tuples (different ports) => three identity keys. The third trips the cap and flushes the first two.
	require.NoError(t, c.Handle(context.Background(), mkConnect(t, "a", 1, 42, "tcp", "outbound", "1.2.3.4", 1, nil)))
	require.NoError(t, c.Handle(context.Background(), mkConnect(t, "b", 2, 42, "tcp", "outbound", "1.2.3.4", 2, nil)))
	require.NoError(t, c.Handle(context.Background(), mkConnect(t, "c", 3, 42, "tcp", "outbound", "1.2.3.4", 3, nil)))
	assert.Len(t, s.events(), 2, "reaching the cap flushes the buffered representatives early")

	c.Flush(context.Background())
	assert.Len(t, s.events(), 3, "the remaining representative flushes normally; nothing is lost")
}

// FuzzCoalescer_Handle drives arbitrary/hostile bytes through Handle's event-JSON parse path. The invariant is that no input ever
// panics and the buffer always drains cleanly (untrusted-input parsing, per the project testing guidelines).
func FuzzCoalescer_Handle(f *testing.F) {
	f.Add([]byte(`{"event_id":"e","host_id":"h","timestamp_ns":1,"event_type":"exec","payload":{"pid":1}}`))
	f.Add([]byte(`{"event_id":"e","host_id":"h","timestamp_ns":1,"event_type":"network_connect","payload":{"pid":1,"remote_port":443}}`))
	f.Add([]byte(`{"event_id":"e","host_id":"h","timestamp_ns":1,"event_type":"dns_query","payload":{"pid":1,"query_name":"x","response_addresses":["1.1.1.1"]}}`))
	f.Add([]byte(`{"event_type":"dns_query","payload":null}`))
	f.Add([]byte(`{"event_type":"network_connect","payload":"not-an-object"}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s := &sink{}
		c := New(time.Second, s.enqueue, nil)
		_ = c.Handle(context.Background(), b) // invariant: never panics
		c.Flush(context.Background())
	})
}

func mkConnect(t require.TestingT, id string, ts int64, pid int, proto, dir, remote string, port int, pidversion *int) []byte {
	payload := map[string]any{
		"pid": pid, "protocol": proto, "direction": dir, "remote_address": remote, "remote_port": port,
	}
	if pidversion != nil {
		payload["pidversion"] = *pidversion
	}
	return mkEnvelope(t, id, ts, "network_connect", payload)
}

func mkDNS(t require.TestingT, id string, ts int64, pid int, name, qtype string, answers []string) []byte {
	payload := map[string]any{"pid": pid, "query_name": name, "query_type": qtype}
	if answers != nil {
		payload["response_addresses"] = answers
	}
	return mkEnvelope(t, id, ts, "dns_query", payload)
}

func mkEnvelope(t require.TestingT, id string, ts int64, typ string, payload map[string]any) []byte {
	pj, err := json.Marshal(payload)
	require.NoError(t, err)
	ej, err := json.Marshal(map[string]any{
		"event_id": id, "host_id": "h", "timestamp_ns": ts, "event_type": typ, "payload": json.RawMessage(pj),
	})
	require.NoError(t, err)
	return ej
}
