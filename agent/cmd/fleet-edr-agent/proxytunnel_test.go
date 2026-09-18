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
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443")
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
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443")
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
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443")
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
	conn, err := dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443")
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

	_, err = dialThroughProxy(t.Context(), failing, proxyURL, "proxy.corp:3128", "edr.example.com:8443")
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

		conn, err := controlDial(recordingDial(&dialed, &mu), proxyURL, proxyURL.Host)(t.Context(), "edr.example.com:8443")
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

		// The dial itself fails, since nothing serves that name here. What is asserted is WHICH address was dialed: unwrapped,
		// with no tunnel in the way.
		_, _ = controlDial(recordingDial(&dialed, &mu), nil, "")(t.Context(), "edr.example.com:8443")

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []string{"edr.example.com:8443"}, dialed)
	})
}

// serverProxy is asked for the proxy of a URL. A URL it cannot parse, and a proxy function that errors, both mean "no proxy" rather
// than a failed dial: the control channel then dials the server directly, which is what it did before a proxy was configured at all.
func TestServerProxyTreatsAnUnusableAnswerAsNoProxy(t *testing.T) {
	t.Parallel()
	failing := func(*http.Request) (*url.URL, error) { return nil, errors.New("PROXY is not a URL") }
	assert.Nil(t, serverProxy("https://edr.example.com:8443", failing))
	assert.Nil(t, serverProxy("://not a url", func(*http.Request) (*url.URL, error) { return url.Parse("http://p:3128") }))

	found := serverProxy("https://edr.example.com:8443", func(*http.Request) (*url.URL, error) { return url.Parse("http://p:3128") })
	require.NotNil(t, found)
	assert.Equal(t, "p:3128", found.Host)
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
	conn, err := dialThroughProxy(ctx, recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Well past the dial's deadline, and the read still succeeds because the deadline was cleared with the exchange.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(8*time.Second)))
	got := make([]byte, len(firstBytes))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err, "the dial's deadline was left on the connection and killed the tunnel")
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
	_, err = dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read CONNECT response")
}

// fakeSOCKS answers one SOCKSv5 connect the way a proxy does and records the destination it was asked for.
type fakeSOCKS struct {
	listener net.Listener
	mu       sync.Mutex
	asked    string
	methods  []byte
}

func newFakeSOCKS(t *testing.T) *fakeSOCKS {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &fakeSOCKS{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, aerr := listener.Accept()
		if aerr != nil {
			return
		}
		s.handle(conn)
	}()
	return s
}

func (s *fakeSOCKS) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}
	methods := make([]byte, greeting[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	s.mu.Lock()
	s.methods = methods
	s.mu.Unlock()
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { // version 5, no authentication
		return
	}
	header := make([]byte, 4) // VER, CMD, RSV, ATYP
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	nameLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, nameLen); err != nil {
		return
	}
	name := make([]byte, int(nameLen[0])+2) // the name plus its two port bytes
	if _, err := io.ReadFull(conn, name); err != nil {
		return
	}
	s.mu.Lock()
	s.asked = string(name[:len(name)-2]) + ":" + strconv.Itoa(int(name[len(name)-2])<<8|int(name[len(name)-1]))
	s.mu.Unlock()
	// Success, bound to 0.0.0.0:0, which is what a proxy answers when the caller does not need the bound address.
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	// Held open so the caller has a connection to close.
	buf := make([]byte, 1)
	_, _ = conn.Read(buf)
}

func (s *fakeSOCKS) destination() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked
}

// A SOCKS proxy gets a SOCKS handshake, not an HTTP CONNECT. containment.TargetFor already treats socks5 as a proxy the lifeline
// keeps reachable, so a contained host can be configured this way, and writing CONNECT at it would simply not connect.
//
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/a-proxied-control-channel-tunnels-through-the-proxy
func TestControlDialSpeaksSOCKSToASOCKSProxy(t *testing.T) {
	t.Parallel()
	socksProxy := newFakeSOCKS(t)
	var mu sync.Mutex
	var dialed []string

	proxyURL, err := url.Parse("socks5://" + socksProxy.listener.Addr().String())
	require.NoError(t, err)
	conn, err := controlDial(recordingDial(&dialed, &mu), proxyURL, proxyURL.Host)(t.Context(), "edr.example.com:8443")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	assert.Equal(t, "edr.example.com:8443", socksProxy.destination(),
		"the server is named inside the SOCKS request, so no resolver on this host is asked for it")
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{socksProxy.listener.Addr().String()}, dialed, "and the proxy itself is reached through the pinned dial")
}

// An https:// proxy is spoken to over TLS. Writing the request in the clear would hand the operator's proxy credentials to anyone
// on the path, which is the opposite of what configuring an https proxy asks for, so a proxy that cannot complete a handshake fails
// the dial rather than falling back.
func TestDialThroughProxyDoesNotSendCredentialsInTheClearToAnHTTPSProxy(t *testing.T) {
	t.Parallel()
	plain := newFakeProxy(t, http.StatusOK, "")
	var mu sync.Mutex
	var dialed []string

	// An https URL pointed at a proxy that speaks no TLS: the handshake must fail before anything is written.
	proxyURL, err := url.Parse("https://ir:s3cret@" + plain.listener.Addr().String())
	require.NoError(t, err)
	_, err = dialThroughProxy(t.Context(), recordingDial(&dialed, &mu), proxyURL, proxyURL.Host, "edr.example.com:8443")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS handshake with proxy")
	assert.Nil(t, plain.seen(), "no request reached the proxy, so no credentials were written")
}
