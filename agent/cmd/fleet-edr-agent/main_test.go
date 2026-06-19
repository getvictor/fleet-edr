package main

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/agent/config"
)

// TestNewAgentHTTPClient builds the shared agent HTTP client (fingerprint/insecure TLS policy + HTTP/2 keep-alive PING config) and
// asserts it constructs cleanly. This covers the http2.ConfigureTransports wiring, which has no other unit coverage.
func TestNewAgentHTTPClient(t *testing.T) {
	t.Parallel()
	transport, client, err := newAgentHTTPClient(&config.Config{AllowInsecure: true}, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, transport)
	require.NotNil(t, client)
}
