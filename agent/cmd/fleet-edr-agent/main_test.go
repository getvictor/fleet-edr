package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/agent/config"
	"github.com/fleetdm/edr/agent/health"
	"github.com/fleetdm/edr/agent/receiver"
)

// TestNewAgentHTTPClient builds the shared agent HTTP client (fingerprint/insecure TLS policy + HTTP/2 keep-alive PING config) and
// asserts it constructs cleanly. This covers the http2.ConfigureTransports wiring, which has no other unit coverage.
func TestNewAgentHTTPClient(t *testing.T) {
	t.Parallel()
	var dialed atomic.Value
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed.Store(addr)
		return nil, errors.New("dial recorded")
	}
	transport, client, err := newAgentHTTPClient(&config.Config{AllowInsecure: true}, dial, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, transport)
	require.NotNil(t, client)
	// Every server connection goes through the given dial, which is what routes a contained host through its lifeline (#948).
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://edr.example.com:8089/api/health", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.ErrorContains(t, err, "dial recorded")
	assert.Equal(t, "edr.example.com:8089", dialed.Load())
}

// TestControlDialTarget pins how the control-channel dial endpoint and transport credentials are derived from EDR_SERVER_URL (issue
// #477: the push channel shares the server's address with the REST path). An https URL dials with TLS credentials; an http URL (dev,
// EDR_ALLOW_INSECURE) dials cleartext with insecure credentials; a missing port defaults to the scheme's standard port.
//
// spec:agent-control-channel/the-agent-derives-the-control-endpoint-from-its-server-url/the-control-endpoint-is-derived-from-the-server-url
func TestControlDialTarget(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		serverURL  string
		allowInsec bool
		wantTarget string
		wantSecure bool // true => TLS transport creds; false => insecure (cleartext h2c)
	}{
		{"https with explicit port", "https://edr.example.com:8088", false, "edr.example.com:8088", true},
		{"https default port", "https://edr.example.com", false, "edr.example.com:443", true},
		{"https self-signed dev", "https://192.168.64.1:8088", true, "192.168.64.1:8088", true},
		{"http dev insecure", "http://127.0.0.1:8088", true, "127.0.0.1:8088", false},
		{"http default port", "http://localhost", true, "localhost:80", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			target, creds, err := controlDialTarget(&config.Config{ServerURL: tc.serverURL, AllowInsecure: tc.allowInsec}, slog.Default())
			require.NoError(t, err)
			require.Equal(t, tc.wantTarget, target)
			require.NotNil(t, creds)
			// The insecure credentials report security level "NoSecurity"; TLS credentials report "tls". This is the stable, public way
			// to assert which transport the agent chose without dialing.
			info := creds.Info()
			if tc.wantSecure {
				require.Equal(t, "tls", info.SecurityProtocol)
			} else {
				require.Equal(t, "insecure", info.SecurityProtocol)
			}
		})
	}
}

// The receiver's stale-upgrade signal reaches the component's reported health, so the console says a restart is needed rather than
// that the extension is not activated.
func TestWithHealthHooks_StaleUpgradeMarksRebootRequired(t *testing.T) {
	t.Parallel()
	registry := health.NewRegistry()
	registry.Register(health.ComponentNetworkExtension, "Network extension")
	hooks := withHealthHooks(receiver.LoopHooks{}, receiverLoopParams{health: registry, component: health.ComponentNetworkExtension})

	require.NotNil(t, hooks.OnUpgradeStale)
	hooks.OnUpgradeStale()
	snap := registry.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, health.StatusUnhealthy, snap[0].Status)
	assert.Equal(t, "reboot_required", snap[0].Reason)

	t.Run("a loop that reports no health gets no health hooks", func(t *testing.T) {
		t.Parallel()
		unwired := withHealthHooks(receiver.LoopHooks{}, receiverLoopParams{})
		assert.Nil(t, unwired.OnUpgradeStale)
		assert.Nil(t, unwired.OnConnected)
	})
}
