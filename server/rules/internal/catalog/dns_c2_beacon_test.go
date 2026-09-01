package catalog

import (
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/rules/api"
)

// TestDNSC2Beacon_TechniquesMapping pins the MITRE ATT&CK union the rule advertises. A given finding narrows this (every
// finding carries T1071.004; only DGA-domain findings add T1568.002), but the rule-level declaration drives the catalog
// surface and ATT&CK-Navigator export, so it is pinned here.
func TestDNSC2Beacon_TechniquesMapping(t *testing.T) {
	t.Parallel()
	r := &DNSC2Beacon{}
	assert.Equal(t, []string{"T1071.004", "T1568.002"}, r.Techniques())
}

func TestShannonEntropyBitsPerChar(t *testing.T) {
	t.Parallel()
	assert.InDelta(t, 0.0, shannonEntropyBitsPerChar(""), 1e-9, "empty string has zero entropy")
	// All-identical characters: zero entropy.
	assert.InDelta(t, 0.0, shannonEntropyBitsPerChar("aaaa"), 1e-9)
	// 16 distinct characters: log2(16) == 4 bits/char.
	assert.InDelta(t, 4.0, shannonEntropyBitsPerChar("abcdefghijklmnop"), 1e-9)
	// A real word carries less entropy than a random label of the same length.
	assert.Less(t, shannonEntropyBitsPerChar("safebrowsing"), shannonEntropyBitsPerChar("kx7gq2vphj9w"))
}

func TestLooksLikeDGADomain(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		domain string
		want   bool
	}{
		{"short normal domain", "www.apple.com", false},
		{"medium real word label", "safebrowsing.googleapis.com", false},
		{"long high-entropy label", "kx7gq2vphj9k3mzw.example.com", true},
		{"high-entropy but too short", "kx7gq2.com", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, looksLikeDGADomain(tc.domain))
		})
	}
}

func TestMostSignificantLabel(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "safebrowsing", mostSignificantLabel("safebrowsing.googleapis.com"))
	assert.Equal(t, "example", mostSignificantLabel("a.example.io"))
	assert.Equal(t, "solo", mostSignificantLabel("solo"))
	assert.Equal(t, "trail", mostSignificantLabel("trail."))
}

func TestAddressResolved(t *testing.T) {
	t.Parallel()
	assert.True(t, addressResolved("203.0.113.10", []string{"198.51.100.1", "203.0.113.10"}))
	assert.False(t, addressResolved("203.0.113.10", []string{"198.51.100.1"}))
	// IPv6 in different valid representations must compare equal.
	assert.True(t, addressResolved("2001:db8::1", []string{"2001:0db8:0000:0000:0000:0000:0000:0001"}))
	assert.False(t, addressResolved("2001:db8::1", []string{"2001:db8::2"}))
	// Non-IP strings fall back to exact match.
	assert.True(t, addressResolved("not-an-ip", []string{"not-an-ip"}))
}

func TestIngestedLookupRange(t *testing.T) {
	t.Parallel()
	// Unset ingest time (fixture replay): full range so the in-memory window still sees every candidate.
	full := ingestedLookupRange(0)
	assert.Equal(t, int64(0), full.FromNs)
	assert.Equal(t, int64(math.MaxInt64), full.ToNs)

	// Known ingest time (production): bounded to the interval from (t minus window minus pad) up to (t plus pad) so a long-lived pid isn't scanned wholesale.
	connectIngested := int64(1_000_000_000_000)
	bounded := ingestedLookupRange(connectIngested)
	assert.Equal(t, connectIngested-dnsBeaconWindowNs-ingestLookupPadNs, bounded.FromNs)
	assert.Equal(t, connectIngested+ingestLookupPadNs, bounded.ToNs)
	assert.Less(t, bounded.FromNs, connectIngested, "lower bound precedes the connection's ingest time")
}

func TestSelectResolvingQuery(t *testing.T) {
	t.Parallel()
	dns := func(id string, ts int64, name string, addrs ...string) detectionapi.Event {
		payload, err := json.Marshal(dnsQueryPayload{PID: 1, QueryName: name, ResponseAddresses: addrs})
		assert.NoError(t, err)
		return detectionapi.Event{EventID: id, EventType: "dns_query", TimestampNs: ts, Payload: payload}
	}
	connectTS := int64(1_000_000_000)

	t.Run("no query resolved the connected address", func(t *testing.T) {
		t.Parallel()
		got, name := selectResolvingQuery([]api.Event{dns("d1", 500, "a.com", "198.51.100.1")}, "203.0.113.10", connectTS)
		assert.Nil(t, got)
		assert.Empty(t, name)
	})

	t.Run("most recent matching query wins", func(t *testing.T) {
		t.Parallel()
		events := []api.Event{
			dns("older", connectTS-2000, "old.com", "203.0.113.10"),
			dns("newer", connectTS-1000, "new.com", "203.0.113.10"),
		}
		got, name := selectResolvingQuery(events, "203.0.113.10", connectTS)
		assert.NotNil(t, got)
		assert.Equal(t, "newer", got.EventID)
		assert.Equal(t, "new.com", name)
	})

	t.Run("tie on timestamp breaks lexicographically on query name", func(t *testing.T) {
		t.Parallel()
		events := []api.Event{
			dns("b", connectTS-1000, "bbb.com", "203.0.113.10"),
			dns("a", connectTS-1000, "aaa.com", "203.0.113.10"),
		}
		got, name := selectResolvingQuery(events, "203.0.113.10", connectTS)
		assert.NotNil(t, got)
		assert.Equal(t, "aaa.com", name)
	})

	t.Run("a query after the connection is not matched", func(t *testing.T) {
		t.Parallel()
		got, _ := selectResolvingQuery([]api.Event{dns("future", connectTS+1, "a.com", "203.0.113.10")}, "203.0.113.10", connectTS)
		assert.Nil(t, got)
	})

	t.Run("a query older than the window is not matched", func(t *testing.T) {
		t.Parallel()
		stale := connectTS - dnsBeaconWindowNs - 1
		got, _ := selectResolvingQuery([]api.Event{dns("stale", stale, "a.com", "203.0.113.10")}, "203.0.113.10", connectTS)
		assert.Nil(t, got)
	})

	t.Run("network_connect events in the slice are ignored", func(t *testing.T) {
		t.Parallel()
		conn := detectionapi.Event{EventID: "nc", EventType: "network_connect", TimestampNs: connectTS - 1, Payload: json.RawMessage(`{}`)}
		got, _ := selectResolvingQuery([]api.Event{conn}, "203.0.113.10", connectTS)
		assert.Nil(t, got)
	})
}

// dnsC2OutboundConnect builds the outbound network_connect the rule keys on, for a pid with no process row, so the tests below
// exercise exactly the flow-process materialization-race branch (resolveFlowProcess returns nil). ingestedAtNs controls which side
// of the flow-process grace window the connect lands on.
func dnsC2OutboundConnect(ingestedAtNs int64) api.Event {
	return api.Event{
		EventID:      "dns-c2-flow-race",
		HostID:       "fixture-host",
		TimestampNs:  1,
		IngestedAtNs: ingestedAtNs,
		EventType:    "network_connect",
		Payload:      json.RawMessage(`{"pid":97531,"direction":"outbound","remote_address":"203.0.113.66","remote_port":443}`),
	}
}

// TestDNSC2Beacon_YoungFlowMissRaisesRetryableError pins the fix for the intermittent demo-nightly drop: with concurrent processor
// batches (issue #535) the network_connect can be evaluated before the batch carrying its exec commits the process row, and the old
// silent skip permanently lost the (Critical) beacon alert. A young connect whose flow process is missing must now fail with the
// retryable sentinel so the processor nacks and re-evaluates the batch once the row lands.
// spec:server-detection-rules-engine/retryable-evaluation-on-unmaterialized-flow-process/a-young-outbound-connect-s-flow-process-row-is-missing
func TestDNSC2Beacon_YoungFlowMissRaisesRetryableError(t *testing.T) {
	t.Parallel()
	gr := &recordingGraphReader{} // byPID + byPIDVersion nil: the flow process has not materialised yet
	evt := dnsC2OutboundConnect(time.Now().UnixNano())
	findings, err := (&DNSC2Beacon{}).Evaluate(t.Context(), []api.Event{evt}, gr)
	require.ErrorIs(t, err, api.ErrProcessNotYetMaterialized,
		"a young outbound connect with no flow process row must fail with the retryable sentinel, not skip silently")
	assert.Empty(t, findings)
}

// TestDNSC2Beacon_StaleFlowMissSkipsSilently pins the bound on the retry: once the connect is older than the tighter
// flowProcessMaterializationGrace, its flow process is assumed to never arrive (the exec was dropped), and evaluation degrades to the
// historical silent skip so a permanently orphaned connect cannot hold its batch in a retry loop.
// spec:server-detection-rules-engine/retryable-evaluation-on-unmaterialized-flow-process/an-outbound-connect-past-the-grace-window-has-no-flow-process-row
func TestDNSC2Beacon_StaleFlowMissSkipsSilently(t *testing.T) {
	t.Parallel()
	gr := &recordingGraphReader{}
	evt := dnsC2OutboundConnect(time.Now().Add(-flowProcessMaterializationGrace - time.Second).UnixNano())
	findings, err := (&DNSC2Beacon{}).Evaluate(t.Context(), []api.Event{evt}, gr)
	require.NoError(t, err, "a connect past the flow-process grace window must not retry")
	assert.Empty(t, findings)
}

// TestDNSC2Beacon_ZeroIngestStampSkipsSilently confirms fixture replay (no ingest stamp) keeps the historical skip on a flow-process
// miss, so the fixture-driven tests and offline replays never spuriously raise the retryable sentinel.
func TestDNSC2Beacon_ZeroIngestStampSkipsSilently(t *testing.T) {
	t.Parallel()
	gr := &recordingGraphReader{}
	evt := dnsC2OutboundConnect(0)
	findings, err := (&DNSC2Beacon{}).Evaluate(t.Context(), []api.Event{evt}, gr)
	require.NoError(t, err, "a zero ingest stamp is never in grace")
	assert.Empty(t, findings)
}

// perPIDGraphReader resolves each pid independently, which recordingGraphReader cannot do (it returns one process for every lookup).
// The masking regression needs a batch where one connect's pid never materialises while another's does.
type perPIDGraphReader struct {
	procByPID      map[int]*api.Process
	netEventsByPID map[int][]api.Event
}

func (r *perPIDGraphReader) GetProcessByPID(_ context.Context, _ string, pid int, _ int64) (*api.Process, error) {
	return r.procByPID[pid], nil
}

func (r *perPIDGraphReader) GetProcessByPIDVersion(_ context.Context, _ string, _ int, _ uint32, _ int64) (*api.Process, error) {
	return nil, nil
}

func (r *perPIDGraphReader) GetChildProcesses(_ context.Context, _ string, _ int, _ api.TimeRange) ([]api.Process, error) {
	return nil, nil
}

func (r *perPIDGraphReader) GetExecChain(_ context.Context, current api.Process) ([]api.Process, error) {
	return []api.Process{current}, nil
}

func (r *perPIDGraphReader) GetHostEventsByType(_ context.Context, _, _ string, _ api.TimeRange) ([]api.Event, error) {
	return nil, nil
}

func (r *perPIDGraphReader) GetNetworkEventsForProcess(_ context.Context, _ string, pid int, _ api.TimeRange) ([]api.Event, error) {
	return r.netEventsByPID[pid], nil
}

// TestDNSC2Beacon_OrphanedConnectDoesNotMaskResolvableBeacon is the named repro for issue #661.
//
// The demo corpus carries captured network_connect events whose fork/exec predate the capture, so their process rows never
// materialise. Those connects reach resolveFlowProcess (which runs BEFORE the suspicion gate) and raise the retryable sentinel on
// every single retry. The rule used to return on the first such event, so a real beacon connect LATER in the same batch was never
// evaluated: the processor nacked and re-claimed every poll tick, the orphan never resolved, and the batch only advanced once the
// orphan aged out of its grace. By then the beacon connect was itself past the grace measured from its own ingest stamp, so it
// degraded to the silent skip and the Critical alert was lost for good.
//
// The rule must now finish the batch: the resolvable beacon fires, and the orphan's miss is still reported so the batch is retried.
// spec:server-detection-rules-engine/retryable-evaluation-on-unmaterialized-flow-process/an-unresolvable-event-does-not-mask-resolvable-findings-in-the-same-batch
func TestDNSC2Beacon_OrphanedConnectDoesNotMaskResolvableBeacon(t *testing.T) {
	t.Parallel()

	const beaconPID = 4242
	now := time.Now().UnixNano()
	beaconProc := &api.Process{ID: 99, HostID: "fixture-host", PID: beaconPID, Path: "/tmp/.update"}
	dnsQuery := api.Event{
		EventID:     "beacon-dns",
		HostID:      "fixture-host",
		EventType:   "dns_query",
		TimestampNs: 500,
		Payload:     json.RawMessage(`{"pid":4242,"query_name":"kx7gq2vphj9k3mzw.example.net","response_addresses":["203.0.113.66"]}`),
	}
	gr := &perPIDGraphReader{
		// 97531 (the orphan, from dnsC2OutboundConnect) is absent: its row never arrives.
		procByPID:      map[int]*api.Process{beaconPID: beaconProc},
		netEventsByPID: map[int][]api.Event{beaconPID: {dnsQuery}},
	}

	beaconConnect := api.Event{
		EventID:      "beacon-connect",
		HostID:       "fixture-host",
		TimestampNs:  1000,
		IngestedAtNs: now,
		EventType:    "network_connect",
		Payload:      json.RawMessage(`{"pid":4242,"direction":"outbound","remote_address":"203.0.113.66","remote_port":443}`),
	}
	// The orphan is deliberately FIRST: that is the ordering the old early return lost the beacon on.
	events := []api.Event{dnsC2OutboundConnect(now), beaconConnect}

	findings, err := (&DNSC2Beacon{}).Evaluate(t.Context(), events, gr)

	require.ErrorIs(t, err, api.ErrProcessNotYetMaterialized,
		"the orphan's miss must still be reported so the processor retries the batch")
	require.Len(t, findings, 1, "the resolvable beacon later in the batch must still fire despite the earlier orphan")
	assert.Equal(t, "dns_c2_beacon", findings[0].RuleID)
	assert.Equal(t, int64(99), findings[0].ProcessID)
	assert.Equal(t, api.SeverityCritical, findings[0].Severity, "a high-entropy domain escalates to Critical")
	assert.Equal(t, []string{"beacon-dns", "beacon-connect"}, findings[0].EventIDs)
}
