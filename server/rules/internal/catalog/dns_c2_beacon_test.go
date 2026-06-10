package catalog

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/rules/api"
)

// spec:server-detection-rules-engine/dns-correlated-c2-beacon-detection/a-suspicious-process-resolves-a-domain-and-connects-to-the-resolved-address
// spec:server-detection-rules-engine/dns-correlated-c2-beacon-detection/a-browser-resolving-and-connecting-to-an-ordinary-domain-does-not-fire
// spec:server-detection-rules-engine/dns-correlated-c2-beacon-detection/a-suspicious-process-that-connects-to-an-address-it-never-resolved-does-not-fire
//
// TestDNSC2Beacon_Fixtures runs every fixture under fixtures/dns_c2_beacon/ as its own sub-test. The positive case is
// the spec scenario above (temp-path process resolves a high-entropy domain, then connects to the resolved address);
// the negatives pin the two non-firing scenarios (a browser-context process; a suspicious process that connects to an
// address it never resolved). Add a case by dropping a *.json file in that directory.
func TestDNSC2Beacon_Fixtures(t *testing.T) {
	t.Parallel()
	detectiontestkit.Replay(t, &DNSC2Beacon{}, "fixtures/dns_c2_beacon")
}

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
