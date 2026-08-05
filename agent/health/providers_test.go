package health

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGradeProviders covers the grading that replaced "an XPC session means healthy" for the network extension (issue #649).
//
// spec:agent-status-reporting/network-extension-health-reflects-capture-provider-liveness/a-report-with-a-running-provider-and-no-fault-is-healthy
// spec:agent-status-reporting/network-extension-health-reflects-capture-provider-liveness/an-extension-with-no-running-capture-provider-is-unhealthy
// spec:agent-status-reporting/network-extension-health-reflects-capture-provider-liveness/a-stopped-capture-provider-is-unhealthy-and-named
// spec:agent-status-reporting/network-extension-health-reflects-capture-provider-liveness/a-deliberately-disabled-provider-does-not-make-the-component-unhealthy
func TestGradeProviders(t *testing.T) {
	t.Parallel()
	const name = "Network extension"
	cases := []struct {
		desc      string
		providers map[string]string
		status    Status
		reason    string
		message   string
	}{
		{
			// The #649 failure itself: the extension process is up and talking, and nothing is capturing. The XPC session is
			// perfectly healthy here, which is exactly why keying on it hid a 24-hour telemetry outage.
			desc:      "no provider started is unhealthy even though XPC is fine",
			providers: map[string]string{},
			status:    StatusUnhealthy,
			reason:    reasonNoProvidersRunning,
			message:   "Network extension is running but no capture provider started",
		},
		{
			desc:      "all providers running is healthy",
			providers: map[string]string{"content_filter": ProviderRunning, "dns_proxy": ProviderRunning},
			status:    StatusHealthy,
			reason:    reasonActivated,
			message:   "Network extension connected",
		},
		{
			// DNS proxying is opt-in. A host that never enabled it reports only the filter, and that is a healthy host, not a
			// degraded one. The extension reports a deliberately-disabled provider as absent for precisely this reason.
			desc:      "an absent provider is opt-out, not a fault",
			providers: map[string]string{"content_filter": ProviderRunning},
			status:    StatusHealthy,
			reason:    reasonActivated,
			message:   "Network extension connected",
		},
		{
			desc:      "a stopped provider is a fault and is named",
			providers: map[string]string{"content_filter": ProviderRunning, "dns_proxy": ProviderStopped},
			status:    StatusUnhealthy,
			reason:    reasonProviderStopped,
			message:   "Network extension stopped capturing: dns_proxy",
		},
		{
			// Names are sorted so the message is stable across map iteration order; an operator diffing two check-ins should
			// not see spurious changes.
			desc:      "multiple stopped providers are listed in a stable order",
			providers: map[string]string{"dns_proxy": ProviderStopped, "content_filter": ProviderStopped},
			status:    StatusUnhealthy,
			reason:    reasonProviderStopped,
			message:   "Network extension stopped capturing: content_filter, dns_proxy",
		},
		{
			// A stopped provider outranks a running one: partial capture is still a capture gap an operator must see.
			desc:      "a stop outranks a running sibling",
			providers: map[string]string{"content_filter": ProviderStopped, "dns_proxy": ProviderRunning},
			status:    StatusUnhealthy,
			reason:    reasonProviderStopped,
			message:   "Network extension stopped capturing: content_filter",
		},
		{
			// Forward compatibility: a provider state this agent does not know counts as neither running nor stopped, so a
			// newer extension cannot make an older agent claim capture it cannot verify.
			desc:      "an unrecognised state does not count as running",
			providers: map[string]string{"content_filter": "reticulating"},
			status:    StatusUnhealthy,
			reason:    reasonNoProvidersRunning,
			message:   "Network extension is running but no capture provider started",
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			status, reason, message := GradeProviders(name, tc.providers)
			assert.Equal(t, tc.status, status)
			assert.Equal(t, tc.reason, reason)
			assert.Equal(t, tc.message, message)
		})
	}
}

// spec:agent-status-reporting/network-extension-health-reflects-capture-provider-liveness/connectivity-without-a-provider-report-is-degraded-not-healthy
func TestMarkProvidersAndAwaiting(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.Register(ComponentNetworkExtension, "Network extension")

	// Registered but never connected.
	require.Len(t, r.Snapshot(), 1)
	assert.Equal(t, StatusUnhealthy, r.Snapshot()[0].Status)

	// An XPC session alone is now degraded, not healthy: that is the whole point of #649.
	r.MarkAwaitingProviders(ComponentNetworkExtension)
	assert.Equal(t, StatusDegraded, r.Snapshot()[0].Status)
	assert.Equal(t, reasonAwaitingProviders, r.Snapshot()[0].Reason)

	// The extension then reports what is actually running.
	r.MarkProviders(ComponentNetworkExtension, map[string]string{"content_filter": ProviderRunning})
	assert.Equal(t, StatusHealthy, r.Snapshot()[0].Status)

	// And a later fault flips it back, still on the same component.
	r.MarkProviders(ComponentNetworkExtension, map[string]string{"content_filter": ProviderStopped})
	assert.Equal(t, StatusUnhealthy, r.Snapshot()[0].Status)
	assert.Equal(t, reasonProviderStopped, r.Snapshot()[0].Reason)

	// Losing the session afterwards reports connection_lost, not never_connected: the component had connected.
	r.MarkDisconnected(ComponentNetworkExtension)
	assert.Equal(t, reasonConnectionLost, r.Snapshot()[0].Reason)
}

func TestMarkProvidersIgnoresUnregisteredComponent(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	// No panic, no phantom component: the loop wires health generically and a misconfigured component must not crash the agent.
	r.MarkProviders(ComponentNetworkExtension, map[string]string{"content_filter": ProviderRunning})
	r.MarkAwaitingProviders(ComponentNetworkExtension)
	assert.Empty(t, r.Snapshot())
}
