package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/agent/config"
	"github.com/fleetdm/edr/agent/containment"
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
	// afterDelay holds afterBody back, standing in for a server that speaks some time after the tunnel opens.
	afterDelay time.Duration
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
	if _, err := io.WriteString(conn, "HTTP/1.1 "+strconv.Itoa(p.status)+" "+status+"\r\n\r\n"); err != nil {
		_ = conn.Close()
		return
	}
	if p.afterBody != "" {
		time.Sleep(p.afterDelay)
		if _, err := io.WriteString(conn, p.afterBody); err != nil {
			_ = conn.Close()
			return
		}
	}
	// Left open: the caller reads what follows the response, which is what a real tunnel carries.
}

func (p *fakeProxy) seen() *http.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.request
}

// recordingDial records every address it was asked to dial, then dials for real. Used where the dial has to reach a fake proxy on
// this machine.
func recordingDial(addrs *[]string, mu *sync.Mutex) dialFunc {
	base := (&net.Dialer{}).DialContext
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		*addrs = append(*addrs, addr)
		mu.Unlock()
		return base(ctx, network, addr)
	}
}

// refusingDial records the address and refuses, without touching the network. Used where the assertion is about WHICH address was
// dialed: dialing a name like edr.example.com for real would put a DNS lookup and its timeout inside a unit test, which is slow when
// it resolves and flaky when it does not.
func refusingDial(addrs *[]string, mu *sync.Mutex) dialFunc {
	return func(_ context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		*addrs = append(*addrs, addr)
		mu.Unlock()
		return nil, errors.New("not dialed by this test")
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
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443", nil)
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
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443", nil)
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
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443", nil)
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
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443", nil)
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

	_, err = dialThroughProxy(t.Context(), failing, proxyURL, "proxy.corp:3128", "edr.example.com:8443", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy.corp:3128")
	assert.Contains(t, err.Error(), "no route")
}

// The dial option is not evidence on its own: what matters is what the dialer gRPC gets actually does. These drive it, which is the
// wiring the earlier test only asserts the presence of.
//
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/a-proxied-control-channel-tunnels-through-the-proxy
func TestControlDialTakesTheRightPath(t *testing.T) {
	t.Parallel()
	proxy := newFakeProxy(t, http.StatusOK, "")

	t.Run("a proxied server is tunnelled", func(t *testing.T) {
		t.Parallel()
		var mu sync.Mutex
		var dialed []string
		proxyURL, err := url.Parse("http://" + proxy.listener.Addr().String())
		require.NoError(t, err)

		conn, err := controlDial(recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, nil)(t.Context(), "edr.example.com:8443")
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []string{proxy.listener.Addr().String()}, dialed, "the proxy is dialed, the server is not")
		assert.Equal(t, "edr.example.com:8443", proxy.seen().Host, "the server is named inside the tunnel")
	})

	t.Run("a direct server is dialed straight through", func(t *testing.T) {
		t.Parallel()
		var mu sync.Mutex
		var dialed []string

		// What is asserted is WHICH address was dialed: unwrapped, with no tunnel in the way. The dial refuses without touching
		// the network, so the test does not depend on what that name resolves to, or on how long it takes to find out.
		_, _ = controlDial(refusingDial(&dialed, &mu), nil, "", nil)(t.Context(), "edr.example.com:8443")

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []string{"edr.example.com:8443"}, dialed)
	})
}

// serverProxy is asked for the proxy of a URL. A URL it cannot parse, and a proxy function that errors, both mean "no proxy" rather
// than a failed dial: the control channel then dials the server directly, which is what it did before a proxy was configured at all.
func TestServerProxyTreatsAnUnusableAnswerAsNoProxy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		desc      string
		serverURL string
		proxy     func(*http.Request) (*url.URL, error)
		want      string // the proxy host expected, or empty for no proxy
	}{
		{
			desc:      "the proxy function errors",
			serverURL: "https://edr.example.com:8443",
			proxy:     func(*http.Request) (*url.URL, error) { return nil, errors.New("PROXY is not a URL") },
		},
		{
			desc:      "the server URL does not parse",
			serverURL: "://not a url",
			proxy:     func(*http.Request) (*url.URL, error) { return url.Parse("http://p:3128") },
		},
		{
			desc:      "a proxy is configured",
			serverURL: "https://edr.example.com:8443",
			proxy:     func(*http.Request) (*url.URL, error) { return url.Parse("http://p:3128") },
			want:      "p:3128",
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			got := serverProxy(tc.serverURL, tc.proxy)
			if tc.want == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tc.want, got.Host)
		})
	}
}

// The dial's deadline must not outlive the dial. A control stream lives for hours on the connection this returns, so a deadline left
// on it would tear the stream down the moment the dial's own timeout would have expired, which is a failure that only appears long
// after the code that caused it.
func TestDialThroughProxyDoesNotLeaveItsDeadlineOnTheTunnel(t *testing.T) {
	t.Parallel()
	const firstBytes = "spoken well after the dial deadline"
	proxy := newFakeProxy(t, http.StatusOK, firstBytes)
	proxy.afterDelay = 1200 * time.Millisecond
	var mu sync.Mutex
	var dialed []string

	proxyURL, err := url.Parse("http://" + proxy.listener.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 600*time.Millisecond)
	defer cancel()
	conn, err := dialThroughProxy(ctx, recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443", nil)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Read with NO deadline of its own. Setting one here would overwrite whatever the dial left behind, so a version that stopped
	// clearing the deadline would still pass: the test would be measuring its own deadline rather than the connection's. The bound
	// comes from a timer beside the read instead.
	got := make([]byte, len(firstBytes))
	read := make(chan error, 1)
	go func() {
		_, rerr := io.ReadFull(conn, got)
		read <- rerr
	}()
	select {
	case rerr := <-read:
		require.NoError(t, rerr, "the dial's deadline was left on the connection and killed the tunnel")
	case <-time.After(8 * time.Second):
		t.Fatal("the tunnel produced nothing within the test's own bound")
	}
	assert.Equal(t, firstBytes, string(got))
}

// A proxy that accepts the connection and then says nothing fails the dial, rather than handing back a connection with no tunnel
// behind it.
func TestDialThroughProxyFailsWhenTheProxySaysNothing(t *testing.T) {
	t.Parallel()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, aerr := listener.Accept()
		if aerr == nil {
			_ = conn.Close() // accepted, then hung up without answering
		}
	}()

	var mu sync.Mutex
	var dialed []string
	proxyURL, perr := url.Parse("http://" + listener.Addr().String())
	require.NoError(t, perr)
	_, err = dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read CONNECT response")
}

// A proxy this build does not speak keeps gRPC's own dialing rather than being handed a request it cannot parse. That is not a
// solution for those deployments, and it is not meant to be: it is what every proxied server did before this change, so the channel
// still cannot reconnect while contained and commands arrive by polling. Taking the dial over regardless would be worse, since an
// unsupported proxy would be sent an HTTP CONNECT carrying the credentials the operator configured on it.
//
// Opted in by scheme rather than ruled out, because net/http hands back whatever is in the environment: `ftp://proxy` parses.
// #1110 added https, socks5 and socks5h to the spoken set; the opt-in shape is what this test pins, not the membership.
func TestControlDialOptionsLeavesUnspokenProxiesAlone(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{ServerURL: "https://edr.example.com:8443"}
	mgr := containment.New(containment.Options{
		Target: containment.Target{Host: "proxy.corp", Port: 3128},
		Send:   func([]byte) error { return nil },
	})
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") }

	// Carrying credentials deliberately: the point of the opt-in is that an unsupported scheme is sent NOTHING, so these never
	// reach a protocol that would misread them.
	for _, scheme := range []string{"ftp", "quic", "socks4"} {
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			proxied := func(*http.Request) (*url.URL, error) { return url.Parse(scheme + "://ir:s3cret@proxy.corp:3128") }
			target, opts := controlDialOptions(cfg, "edr.example.com:8443", mgr, dial, proxied, nil)
			assert.Equal(t, "edr.example.com:8443", target, "gRPC resolves and dials it, as it did before this change")
			assert.Empty(t, opts, "no dialer of ours, so nothing writes a request this proxy cannot parse")
		})
	}

	// Every scheme this build speaks is taken over: HTTP and HTTPS by CONNECT, SOCKS5 by its own handshake (issue #1110).
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		t.Run(scheme+" is taken over", func(t *testing.T) {
			t.Parallel()
			proxied := func(*http.Request) (*url.URL, error) { return url.Parse(scheme + "://proxy.corp:3128") }
			target, opts := controlDialOptions(cfg, "edr.example.com:8443", mgr, dial, proxied, nil)
			assert.Equal(t, "passthrough:///edr.example.com:8443", target)
			assert.Len(t, opts, 1)
		})
	}
}

// A caller that gives up must not leave the dial sitting on a connection nobody is waiting for. A cancelled context does not
// interrupt a read already in progress, so without something to unblock it this waits for the socket itself to fail, which on a
// silent proxy is minutes.
func TestDialThroughProxyStopsWhenTheCallerGivesUp(t *testing.T) {
	t.Parallel()
	// A listener that accepts and then says nothing at all, which is what a wedged proxy looks like.
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, aerr := listener.Accept()
		if aerr == nil {
			accepted <- conn
		}
	}()

	proxyURL, err := url.Parse("http://" + listener.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	var mu sync.Mutex
	var dialed []string

	done := make(chan error, 1)
	go func() {
		_, derr := dialThroughProxy(ctx, recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443", nil)
		done <- derr
	}()

	// Let the CONNECT reach the proxy, then give up on it.
	select {
	case conn := <-accepted:
		t.Cleanup(func() { _ = conn.Close() })
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy was never dialed")
	}
	cancel()

	select {
	case derr := <-done:
		require.Error(t, derr, "a cancelled dial does not return a usable connection")
	case <-time.After(10 * time.Second):
		t.Fatal("the dial did not return after its context was cancelled")
	}
}

// socks5Server is a minimal SOCKS5 proxy for these tests: it records what the client asked for and then joins the two sides, so a
// test can assert on the handshake AND on bytes crossing the finished tunnel.
type socks5Server struct {
	listener net.Listener
	mu       sync.Mutex
	// dest is the destination as the CLIENT expressed it, which is the interesting half: a name means the proxy was asked to
	// resolve, which is the only thing that works from a contained host.
	dest string
	// offeredUserPass records whether the client offered username/password authentication in its greeting.
	offeredUserPass bool
	creds           string
}

func newSOCKS5Server(t *testing.T, requireAuth bool) *socks5Server {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &socks5Server{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, aerr := listener.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		s.serve(conn, requireAuth)
	}()
	return s
}

// serve speaks just enough of RFC 1928 and RFC 1929 to complete a CONNECT, then echoes, so the test can prove the tunnel carries
// traffic rather than only that the handshake returned.
func (s *socks5Server) serve(conn net.Conn, requireAuth bool) {
	reader := bufio.NewReader(conn)
	version, _ := reader.ReadByte()
	if version != 5 {
		return
	}
	methodCount, _ := reader.ReadByte()
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}
	s.mu.Lock()
	s.offeredUserPass = bytes.Contains(methods, []byte{0x02})
	s.mu.Unlock()
	if requireAuth {
		if _, err := conn.Write([]byte{5, 0x02}); err != nil {
			return
		}
		_, _ = reader.ReadByte() // auth version
		userLen, _ := reader.ReadByte()
		user := make([]byte, userLen)
		if _, err := io.ReadFull(reader, user); err != nil {
			return
		}
		passLen, _ := reader.ReadByte()
		pass := make([]byte, passLen)
		if _, err := io.ReadFull(reader, pass); err != nil {
			return
		}
		s.mu.Lock()
		s.creds = string(user) + ":" + string(pass)
		s.mu.Unlock()
		if _, err := conn.Write([]byte{1, 0}); err != nil {
			return
		}
	} else if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	header := make([]byte, 4) // version, command, reserved, address type
	if _, err := io.ReadFull(reader, header); err != nil {
		return
	}
	var host string
	switch header[3] {
	case 0x03: // a NAME, which is what a contained host must send
		nameLen, _ := reader.ReadByte()
		name := make([]byte, nameLen)
		if _, err := io.ReadFull(reader, name); err != nil {
			return
		}
		host = string(name)
	case 0x01: // an IPv4 address, meaning the client resolved locally
		addr := make([]byte, 4)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(reader, port); err != nil {
		return
	}
	s.mu.Lock()
	s.dest = net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1])))
	s.mu.Unlock()
	// Success, bound to 0.0.0.0:0, which is what a proxy that does not report its bound address returns.
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_, _ = io.Copy(conn, reader) // echo the tunnel
}

func (s *socks5Server) observed() (dest, creds string, offeredUserPass bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dest, s.creds, s.offeredUserPass
}

// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/a-socks5-proxy-is-spoken-to-in-its-own-protocol
func TestDialThroughSOCKS5Proxy(t *testing.T) {
	t.Parallel()
	server := newSOCKS5Server(t, false)
	proxyURL, err := url.Parse("socks5://" + server.listener.Addr().String())
	require.NoError(t, err)
	var dialed []string
	var mu sync.Mutex

	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL,
		server.listener.Addr().String(), "edr.example.com:8443", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	dest, _, _ := server.observed()
	assert.Equal(t, "edr.example.com:8443", dest,
		"the destination must cross as a NAME for the proxy to resolve; a contained host cannot resolve it itself")
	mu.Lock()
	dialedProxy := slices.Clone(dialed)
	mu.Unlock()
	require.Len(t, dialedProxy, 1, "exactly one dial, and it is the proxy's pinned address")
	assert.Equal(t, server.listener.Addr().String(), dialedProxy[0],
		"the proxy is reached through the containment dial, which is what puts it on the lifeline")

	// The tunnel carries traffic, not just a handshake that returned.
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	echoed := make([]byte, 4)
	_, err = io.ReadFull(conn, echoed)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(echoed))
}

// The operator's proxy credentials are offered to a SOCKS5 proxy the way net/http offers them to an HTTP one, so a proxy that
// authenticates the agent's uploads authenticates its control channel.
//
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/a-socks5-proxy-is-spoken-to-in-its-own-protocol
func TestDialThroughSOCKS5ProxyOffersCredentials(t *testing.T) {
	t.Parallel()
	server := newSOCKS5Server(t, true)
	proxyURL, err := url.Parse("socks5h://ir:s3cret@" + server.listener.Addr().String())
	require.NoError(t, err)
	var dialed []string
	var mu sync.Mutex

	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL,
		server.listener.Addr().String(), "edr.example.com:8443", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, creds, offered := server.observed()
	assert.True(t, offered, "username/password must be offered when the proxy URL carries it")
	assert.Equal(t, "ir:s3cret", creds)
}

// selfSignedTLS builds a certificate for 127.0.0.1, so an https-proxy test has something to present without a fixture on disk.
func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "proxy.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		// Both, so one test can verify by address and another by the proxy URL's own name.
		DNSNames:    []string{"proxy.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
}

// The credentials an operator configures on an https proxy must not cross the path in the clear. This is the whole reason the
// scheme needs its own branch rather than reusing the HTTP one, so it is asserted on the bytes rather than inferred from the code.
//
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/an-https-proxy-is-reached-over-tls-first
func TestDialThroughHTTPSProxySpeaksTLSBeforeTheConnect(t *testing.T) {
	t.Parallel()
	// A PLAIN listener, deliberately: it lets the test read the first bytes the agent writes, which is the claim under test.
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	firstBytes := make(chan []byte, 1)
	go func() {
		conn, aerr := listener.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 16)
		n, rerr := conn.Read(buf)
		if rerr != nil {
			firstBytes <- nil
			return
		}
		firstBytes <- buf[:n]
	}()

	proxyURL, err := url.Parse("https://ir:s3cret@" + listener.Addr().String())
	require.NoError(t, err)
	var dialed []string
	var mu sync.Mutex
	// The handshake cannot complete against a listener that speaks no TLS; the assertion is about what was SENT.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, _ = dialThroughProxy(ctx, recordingDial(&dialed, &mu), proxyURL, listener.Addr().String(),
		"edr.example.com:8443", &tls.Config{MinVersion: tls.VersionTLS12})

	var sent []byte
	select {
	case sent = <-firstBytes:
	case <-time.After(3 * time.Second):
		t.Fatal("the agent wrote nothing to the proxy")
	}
	require.NotEmpty(t, sent)
	assert.EqualValues(t, 0x16, sent[0],
		"the first byte must open a TLS handshake record, not a CONNECT that would carry the operator's credentials in the clear")
	assert.NotContains(t, string(sent), "CONNECT")
	assert.NotContains(t, string(sent), "Proxy-Authorization")
}

// A proxy certificate the agent's own TLS policy rejects must fail the dial, and say which proxy, rather than failing somewhere
// that reads as the server being unreachable.
//
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/an-https-proxy-is-reached-over-tls-first
func TestDialThroughHTTPSProxyRejectsAnUntrustedCertificate(t *testing.T) {
	t.Parallel()
	serverTLS := selfSignedTLS(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, aerr := listener.Accept()
		if aerr != nil {
			return
		}
		_ = conn.(*tls.Conn).HandshakeContext(context.Background())
		_ = conn.Close()
	}()

	proxyURL, err := url.Parse("https://" + listener.Addr().String())
	require.NoError(t, err)
	var dialed []string
	var mu sync.Mutex

	// The agent's policy with neither AllowInsecure nor a pinned fingerprint: an unknown authority is rejected.
	_, err = dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, listener.Addr().String(),
		"edr.example.com:8443", &tls.Config{MinVersion: tls.VersionTLS12})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS handshake with proxy")
	assert.Contains(t, err.Error(), proxyURL.Host, "the message must name the proxy, not just the failure")
}

// The positive half: a certificate the agent's policy DOES accept completes the handshake, and the CONNECT then goes over it.
//
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/an-https-proxy-is-reached-over-tls-first
func TestDialThroughHTTPSProxyTunnelsOverTLS(t *testing.T) {
	t.Parallel()
	serverTLS := selfSignedTLS(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	authorized := make(chan string, 1)
	go func() {
		conn, aerr := listener.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		req, rerr := http.ReadRequest(reader)
		if rerr != nil {
			authorized <- ""
			return
		}
		authorized <- req.Header.Get("Proxy-Authorization")
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		_, _ = io.Copy(conn, reader)
	}()

	proxyURL, err := url.Parse("https://ir:s3cret@" + listener.Addr().String())
	require.NoError(t, err)
	var dialed []string
	var mu sync.Mutex

	// InsecureSkipVerify stands in for "a certificate this deployment's policy accepts", which is what EDR_ALLOW_INSECURE or a
	// private CA in the agent's own configuration produces.
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, listener.Addr().String(),
		"edr.example.com:8443", &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}) //nolint:gosec // test fixture
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("ir:s3cret")), <-authorized,
		"the credentials still reach the proxy, now inside TLS")
	_, err = conn.Write([]byte("pong"))
	require.NoError(t, err)
	echoed := make([]byte, 4)
	_, err = io.ReadFull(conn, echoed)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(echoed))
}

// The certificate is checked against the PROXY's name, not the server's and not the address it was pinned to. The proxy is
// reached at an address (its name is what a contained host cannot resolve), so nothing in the dial carries the name that the
// certificate has to match; it has to come from the proxy URL.
//
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/an-https-proxy-is-reached-over-tls-first
func TestDialThroughHTTPSProxyVerifiesTheProxysOwnName(t *testing.T) {
	t.Parallel()
	serverTLS := selfSignedTLS(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, aerr := listener.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		if _, rerr := http.ReadRequest(reader); rerr != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		_, _ = io.Copy(conn, reader)
	}()

	// A pool trusting that certificate, which stands in for the private CA an operator configures. Verification is real: only the
	// NAME is in question.
	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(serverTLS.Certificates[0].Certificate[0])
	require.NoError(t, err)
	pool.AddCert(leaf)

	// The proxy is NAMED proxy.test and REACHED at 127.0.0.1: exactly the contained-host shape.
	proxyURL, err := url.Parse("https://proxy.test:3128")
	require.NoError(t, err)
	var dialed []string
	var mu sync.Mutex

	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, listener.Addr().String(),
		"edr.example.com:8443", &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool})
	require.NoError(t, err, "the certificate is valid for proxy.test, so the handshake must verify against that name")
	t.Cleanup(func() { _ = conn.Close() })

	mu.Lock()
	dialedProxy := slices.Clone(dialed)
	mu.Unlock()
	require.Len(t, dialedProxy, 1)
	assert.Equal(t, listener.Addr().String(), dialedProxy[0], "reached at the pinned address, verified under its own name")
}

// pinnedDialer exists to satisfy proxy.Dialer, whose Dial carries no context. The SOCKS5 library prefers DialContext and so never
// calls it, but the method is part of the contract the library type-asserts against, and it must pin the same address: a version
// that honoured the address it was handed would resolve the proxy's name, which is the thing a contained host cannot do.
//
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/a-socks5-proxy-is-spoken-to-in-its-own-protocol
func TestPinnedDialerAlwaysDialsThePinnedAddress(t *testing.T) {
	t.Parallel()
	var dialed []string
	var mu sync.Mutex
	record := func(_ context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		return nil, errors.New("not connecting, only recording")
	}
	dialer := pinnedDialer{dial: record, addr: "10.0.0.9:1080"}

	_, err := dialer.Dial("tcp", "proxy.corp:1080")
	require.Error(t, err)
	_, err = dialer.DialContext(t.Context(), "tcp", "proxy.corp:1080")
	require.Error(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"10.0.0.9:1080", "10.0.0.9:1080"}, dialed,
		"both methods must dial the pinned address, never the name they were handed")
}

// The failure an operator actually meets: the proxy is there but refuses the CONNECT, or is not there at all. It must fail the
// dial naming the proxy and the destination, rather than surfacing as an unexplained transport error.
//
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/a-socks5-proxy-is-spoken-to-in-its-own-protocol
func TestDialThroughSOCKS5ProxyReportsARefusal(t *testing.T) {
	t.Parallel()
	// A listener that accepts and immediately closes, which is what a proxy refusing the handshake looks like.
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, aerr := listener.Accept()
		if aerr != nil {
			return
		}
		_ = conn.Close()
	}()

	proxyURL, err := url.Parse("socks5://" + listener.Addr().String())
	require.NoError(t, err)
	var dialed []string
	var mu sync.Mutex

	_, err = dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL,
		listener.Addr().String(), "edr.example.com:8443", nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "SOCKS5 proxy "+listener.Addr().String())
	assert.Contains(t, err.Error(), "edr.example.com:8443", "the destination belongs in the message too")
}

// A SOCKS5 dial whose caller gives up must fail promptly, the same as the CONNECT path, rather than sit on a proxy that accepted
// the connection and then went quiet.
//
// The interruption is x/net's rather than ours: socks.Dialer.connect watches ctx.Done() and stamps a past deadline on the
// connection to unblock its reads, then stops and waits for that watcher before returning, which is the same mechanism
// connectThrough implements by hand. This test exists because that is a property of a DEPENDENCY: nothing in this repository
// would fail if a future x/net stopped honouring cancellation mid-handshake, and the symptom would be a control-channel dial
// wedged on a silent proxy, on a path that only runs while a host is contained.
//
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/a-socks5-proxy-is-spoken-to-in-its-own-protocol
func TestDialThroughSOCKS5StopsWhenTheCallerGivesUp(t *testing.T) {
	t.Parallel()
	// Accepts, then says nothing at all: a proxy that completed TCP and stalled in the handshake.
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, aerr := listener.Accept()
		if aerr != nil {
			return
		}
		accepted <- conn
	}()

	proxyURL, err := url.Parse("socks5://" + listener.Addr().String())
	require.NoError(t, err)
	var dialed []string
	var mu sync.Mutex
	// No deadline on the context: cancellation alone has to be what unblocks it, which is the half a deadline would hide.
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, derr := dialThroughProxy(ctx, recordingDial(&dialed, &mu), proxyURL,
			listener.Addr().String(), "edr.example.com:8443", nil)
		done <- derr
	}()

	// Cancel only once the proxy has the connection and the handshake is genuinely in flight.
	select {
	case conn := <-accepted:
		t.Cleanup(func() { _ = conn.Close() })
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("the proxy never received the connection")
	}
	cancel()

	select {
	case derr := <-done:
		require.Error(t, derr, "a cancelled dial must fail, not return a tunnel nobody is waiting for")
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled SOCKS5 dial did not return; it is waiting out a silent proxy")
	}
}
