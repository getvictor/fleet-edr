package enrollment

import (
	"log/slog"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Enrollment goes through the agent's proxy like the rest of its traffic. Its transport is a clone of http.DefaultTransport, so
// without this the inherited ProxyFromEnvironment would read the real process environment while every other connection used the
// agent's own configuration, and a host would enrol direct and then talk through a proxy, or fail to enrol at all (issue #1117).
func TestTheEnrollmentTransportUsesTheSuppliedProxy(t *testing.T) {
	t.Parallel()
	want, err := url.Parse("http://proxy.corp:3128")
	require.NoError(t, err)
	p := &provider{
		opts:   Options{Proxy: func(*http.Request) (*url.URL, error) { return want, nil }},
		logger: slog.Default(),
	}

	client, err := p.httpClient()
	require.NoError(t, err)

	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, tr.Proxy)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://edr.example.com:8443/api/enroll", nil)
	require.NoError(t, err)
	got, err := tr.Proxy(req)
	require.NoError(t, err)
	assert.Equal(t, want.String(), got.String())
}

// A caller that supplies none keeps the stdlib's behaviour rather than getting a nil chooser that would panic on the first dial.
func TestNoSuppliedProxyLeavesTheTransportsOwn(t *testing.T) {
	t.Parallel()
	p := &provider{logger: slog.Default()}

	client, err := p.httpClient()
	require.NoError(t, err)

	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.NotNil(t, tr.Proxy, "the clone's inherited chooser stays in place")
}
