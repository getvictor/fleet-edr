package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProxy is a listener that answers one CONNECT the way a proxy does, records what it was asked, and then hands the connection
// over to whatever the tunnel carries.
type fakeProxy struct {
	listener net.Listener
	mu       sync.Mutex
	// request is the CONNECT line and headers the agent sent.
	request *http.Request
	// status is what the proxy answers with, and afterBody is what it writes immediately after the response, standing in for the
	// first bytes the tunnelled server sends.
	status    int
	afterBody string
}

func newFakeProxy(t *testing.T, status int, afterBody string) *fakeProxy {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &fakeProxy{listener: listener, status: status, afterBody: afterBody}
	t.Cleanup(func() { _ = listener.Close() })
	go p.serve()
	return p
}

func (p *fakeProxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *fakeProxy) handle(conn net.Conn) {
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		_ = conn.Close()
		return
	}
	p.mu.Lock()
	p.request = req
	p.mu.Unlock()
	status := http.StatusText(p.status)
	if _, err := io.WriteString(conn, "HTTP/1.1 "+strconv.Itoa(p.status)+" "+status+"\r\n\r\n"+p.afterBody); err != nil {
		_ = conn.Close()
		return
	}
	// Left open: the caller reads what follows the response, which is what a real tunnel carries.
}

func (p *fakeProxy) seen() *http.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.request
}

// recordingDial records every address it was asked to dial, then dials for real.
func recordingDial(addrs *[]string, mu *sync.Mutex) dialFunc {
	base := (&net.Dialer{}).DialContext
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		*addrs = append(*addrs, addr)
		mu.Unlock()
		return base(ctx, network, addr)
	}
}

// The tunnel is what makes the control channel reconnect on a contained host: the dial goes to the PROXY, which the containment
// manager pins to lifeline addresses, and the server is named only inside the CONNECT, where no resolver is involved.
//
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/a-proxied-control-channel-tunnels-through-the-proxy
func TestDialThroughProxyTunnelsToTheServer(t *testing.T) {
	t.Parallel()
	proxy := newFakeProxy(t, http.StatusOK, "")
	var mu sync.Mutex
	var dialed []string

	proxyURL, err := url.Parse("http://" + proxy.listener.Addr().String())
	require.NoError(t, err)
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, "edr.example.com:8443")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{proxy.listener.Addr().String()}, dialed,
		"the dial must go to the proxy: the server's name is what a contained host cannot resolve")

	seen := proxy.seen()
	require.NotNil(t, seen)
	assert.Equal(t, http.MethodConnect, seen.Method)
	assert.Equal(t, "edr.example.com:8443", seen.Host, "the server is named in the CONNECT, not dialed")
	assert.Empty(t, seen.Header.Get("Proxy-Authorization"), "no user info in the proxy URL means no credentials are invented")
}

// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/a-proxied-control-channel-tunnels-through-the-proxy
func TestDialThroughProxySendsCredentialsFromTheProxyURL(t *testing.T) {
	t.Parallel()
	proxy := newFakeProxy(t, http.StatusOK, "")
	var mu sync.Mutex
	var dialed []string

	proxyURL, err := url.Parse("http://ir:s3cret@" + proxy.listener.Addr().String())
	require.NoError(t, err)
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, "edr.example.com:8443")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	seen := proxy.seen()
	require.NotNil(t, seen)
	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("ir:s3cret")), seen.Header.Get("Proxy-Authorization"),
		"a proxy that authenticates the agent's HTTP traffic must authenticate this the same way")
}

// A proxy that refuses is a failed dial, not a connection that looks open and then carries nothing. gRPC would otherwise run TLS
// over the proxy's error page.
func TestDialThroughProxyFailsWhenTheProxyRefuses(t *testing.T) {
	t.Parallel()
	proxy := newFakeProxy(t, http.StatusForbidden, "")
	var mu sync.Mutex
	var dialed []string

	proxyURL, err := url.Parse("http://" + proxy.listener.Addr().String())
	require.NoError(t, err)
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, "edr.example.com:8443")
	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "403")
}

// The response must be read to its end and no further. A buffered reader that read ahead would swallow the first bytes the server
// sent, which for gRPC is the start of the TLS handshake: the channel would then hang rather than fail, on a path that only runs
// while a host is contained.
func TestDialThroughProxyLeavesTheTunnelsFirstBytes(t *testing.T) {
	t.Parallel()
	const firstBytes = "the server speaks first"
	proxy := newFakeProxy(t, http.StatusOK, firstBytes)
	var mu sync.Mutex
	var dialed []string

	proxyURL, err := url.Parse("http://" + proxy.listener.Addr().String())
	require.NoError(t, err)
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, "edr.example.com:8443")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	got := make([]byte, len(firstBytes))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	assert.Equal(t, firstBytes, string(got))
}

// A dial that cannot reach the proxy at all reports the proxy, so an operator reading the log is pointed at the hop that failed
// rather than at the server.
func TestDialThroughProxyReportsTheProxyItCouldNotReach(t *testing.T) {
	t.Parallel()
	failing := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no route") }
	proxyURL, err := url.Parse("http://proxy.corp:3128")
	require.NoError(t, err)

	_, err = dialThroughProxy(t.Context(), failing, proxyURL, "edr.example.com:8443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy.corp:3128")
	assert.Contains(t, err.Error(), "no route")
}

func TestProxyAddressDefaultsThePortByScheme(t *testing.T) {
	t.Parallel()
	cases := []struct {
		given string
		want  string
	}{
		{given: "http://proxy.corp:3128", want: "proxy.corp:3128"},
		{given: "http://proxy.corp", want: "proxy.corp:80"},
		{given: "https://proxy.corp", want: "proxy.corp:443"},
		{given: "https://proxy.corp:8443", want: "proxy.corp:8443"},
		// #nosec G101 -- a proxy URL carrying user info, which is the case under test, not a credential.
		{given: "http://ir:s3cret@proxy.corp", want: "proxy.corp:80"},
	}
	for _, tc := range cases {
		t.Run(tc.given, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(tc.given)
			require.NoError(t, err)
			assert.Equal(t, tc.want, proxyAddress(u))
		})
	}
}
