package health

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// componentByType indexes a snapshot so a test asserts on the condition it means rather than on a position that shifts
// whenever a component is added.
func componentByType(snapshot []Component) map[string]Component {
	out := make(map[string]Component, len(snapshot))
	for _, c := range snapshot {
		out[c.Type] = c
	}
	return out
}

// spec:agent-status-reporting/the-agent-reports-each-capture-provider-as-its-own-component/each-reported-provider-appears-as-its-own-component
//
// The collapsed parent component alone cannot say which providers are capturing, so a wedged provider and a fully working
// host look identical on the wire. These are the positive per-provider claims the server contradicts against the telemetry
// actually arriving.
func TestSnapshot_ReportsEachProviderAsItsOwnComponent(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(fixedClock(100))
	r.Register(ComponentNetworkExtension, "Network extension")
	r.MarkProviders(ComponentNetworkExtension, map[string]string{
		ProviderContentFilter: ProviderRunning,
		ProviderDNSProxy:      ProviderStopped,
	})

	byType := componentByType(r.Snapshot())

	require.Contains(t, byType, ComponentNetworkExtension, "the collapsed parent must still be reported, unchanged")
	assert.Equal(t, StatusUnhealthy, byType[ComponentNetworkExtension].Status, "one stopped provider still condemns the parent")

	require.Contains(t, byType, ProviderContentFilter)
	assert.Equal(t, StatusHealthy, byType[ProviderContentFilter].Status)
	assert.Equal(t, reasonActivated, byType[ProviderContentFilter].Reason)
	assert.Contains(t, byType[ProviderContentFilter].Message, "Content filter")

	require.Contains(t, byType, ProviderDNSProxy)
	assert.Equal(t, StatusUnhealthy, byType[ProviderDNSProxy].Status)
	assert.Equal(t, reasonProviderStopped, byType[ProviderDNSProxy].Reason)
	assert.Contains(t, byType[ProviderDNSProxy].Message, "DNS proxy")
}

// spec:agent-status-reporting/the-agent-reports-each-capture-provider-as-its-own-component/a-provider-the-extension-stops-reporting-is-dropped
//
// This is the case the whole design turns on. The extension reports a deliberate opt-out by OMITTING the provider, so a
// registry that accumulated providers would keep publishing "running" for one an operator switched off. That stale claim is
// worse than silence: the server contradicts these claims against arriving telemetry, so it would report a wedge on a
// provider that is simply off, which is the false positive this change exists to remove.
func TestSnapshot_DropsAProviderTheExtensionStopsReporting(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(seqClock(1000))
	r.Register(ComponentNetworkExtension, "Network extension")
	r.MarkProviders(ComponentNetworkExtension, map[string]string{
		ProviderContentFilter: ProviderRunning,
		ProviderDNSProxy:      ProviderRunning,
	})
	require.Contains(t, componentByType(r.Snapshot()), ProviderDNSProxy)

	// The operator disables the optional DNS proxy: the extension now omits it entirely.
	r.MarkProviders(ComponentNetworkExtension, map[string]string{ProviderContentFilter: ProviderRunning})

	byType := componentByType(r.Snapshot())
	assert.NotContains(t, byType, ProviderDNSProxy,
		"a provider the extension no longer reports must vanish, not linger asserting its last state")
	assert.Contains(t, byType, ProviderContentFilter, "the provider still reported is unaffected")
	assert.Equal(t, StatusHealthy, byType[ComponentNetworkExtension].Status,
		"and a deliberate opt-out must not condemn the parent either")
}

// spec:agent-status-reporting/the-agent-reports-each-capture-provider-as-its-own-component/an-unchanged-provider-keeps-its-transition-instant
//
// TestSnapshot_KeepsTheTransitionInstantWhileAProviderIsUnchanged pins the age the console renders. Liveness reports arrive
// on every agent handshake, so re-stamping on each one would make every provider look like it had just changed and destroy
// the "stopped 4m ago" an operator reads.
func TestSnapshot_KeepsTheTransitionInstantWhileAProviderIsUnchanged(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(seqClock(1000))
	r.Register(ComponentNetworkExtension, "Network extension")

	r.MarkProviders(ComponentNetworkExtension, map[string]string{ProviderContentFilter: ProviderRunning})
	first := componentByType(r.Snapshot())[ProviderContentFilter].LastTransitionNs
	require.Positive(t, first)

	for range 3 {
		r.MarkProviders(ComponentNetworkExtension, map[string]string{ProviderContentFilter: ProviderRunning})
	}
	assert.Equal(t, first, componentByType(r.Snapshot())[ProviderContentFilter].LastTransitionNs,
		"an unchanged provider keeps its instant across repeated reports")

	// A real state change does advance it.
	r.MarkProviders(ComponentNetworkExtension, map[string]string{ProviderContentFilter: ProviderStopped})
	assert.Greater(t, componentByType(r.Snapshot())[ProviderContentFilter].LastTransitionNs, first,
		"a genuine transition must re-stamp")
}

// spec:agent-status-reporting/the-agent-reports-each-capture-provider-as-its-own-component/an-unrecognised-provider-state-is-reported-as-unknown
//
// TestSnapshot_GradesAnUnrecognizedProviderStateAsUnknown covers a newer extension reporting a state this build predates.
// Unknown is the only safe grade in both directions: it is not a positive running claim the server could contradict into a
// false alert, and it does not condemn a host either.
func TestSnapshot_GradesAnUnrecognizedProviderStateAsUnknown(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(fixedClock(100))
	r.Register(ComponentNetworkExtension, "Network extension")
	r.MarkProviders(ComponentNetworkExtension, map[string]string{"future_provider": "reconfiguring"})

	got := componentByType(r.Snapshot())["future_provider"]
	assert.Equal(t, StatusUnknown, got.Status)
	assert.Equal(t, reasonProviderStateUnknown, got.Reason)
	assert.Contains(t, got.Message, "future_provider", "an unknown provider is still legible under its own identifier")
}

// TestSnapshot_OrdersProvidersStably pins the wire against map iteration order. The server upserts the snapshot
// last-writer-wins and the report is compared as a whole, so an unstable order would make every identical report look like
// a change.
func TestSnapshot_OrdersProvidersStably(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(fixedClock(100))
	r.Register(ComponentNetworkExtension, "Network extension")
	report := map[string]string{
		ProviderDNSProxy:      ProviderRunning,
		ProviderContentFilter: ProviderRunning,
		"zz_last":             ProviderRunning,
		"aa_first":            ProviderRunning,
	}
	want := []string{ComponentNetworkExtension, "aa_first", ProviderContentFilter, ProviderDNSProxy, "zz_last"}

	// Repeated identical reports must produce byte-identical order, which is what rules out map iteration order.
	for range 5 {
		r.MarkProviders(ComponentNetworkExtension, report)
		got := make([]string, 0, len(want))
		for _, c := range r.Snapshot() {
			got = append(got, c.Type)
		}
		assert.Equal(t, want, got, "providers follow their parent, sorted by identifier")
	}
}

// TestMarkProviders_IgnoresAnUnregisteredParent matches the transition contract: a report for a component this build does
// not monitor must not conjure providers under it.
func TestMarkProviders_IgnoresAnUnregisteredParent(t *testing.T) {
	t.Parallel()
	r := newRegistryWithClock(fixedClock(100))
	r.MarkProviders(ComponentNetworkExtension, map[string]string{ProviderContentFilter: ProviderRunning})
	assert.Empty(t, r.Snapshot())
}
