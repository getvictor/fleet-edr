package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"time"

	"golang.org/x/net/proxy"
	"google.golang.org/grpc"

	"github.com/fleetdm/edr/agent/config"
	"github.com/fleetdm/edr/agent/containment"
)

// dialFunc is the dial every connection to the server goes through.
type dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

// The base dial matches http.DefaultTransport's, which the agent transports clone.
const (
	serverDialTimeout   = 30 * time.Second
	serverDialKeepAlive = 30 * time.Second
)

// baseServerDial is the dial a server connection uses when the lifeline does not apply to it.
func baseServerDial() dialFunc {
	return (&net.Dialer{Timeout: serverDialTimeout, KeepAlive: serverDialKeepAlive}).DialContext
}

// newContainment builds the network containment manager (#948) and the dial every server connection uses: the enrollment client, the
// shared agent transport and the control channel. While the host is contained, that dial reaches the server through the lifeline
// addresses, because the system resolver answers nothing then. Only macOS has a network extension to contain with; elsewhere, and when
// the server URL yields no lifeline target, there is no manager, set_network_containment reports failed, and the dial is base.
func newContainment(cfg *config.Config, send func([]byte) error, base dialFunc, logger *slog.Logger,
	statePath string) (*containment.Manager, dialFunc) {
	if runtime.GOOS != "darwin" || cfg.NetXPCService == "" {
		return nil, base
	}
	// The agent's own proxy, not the process environment's: the lifeline must pin whatever the REST of the agent dials, or a
	// contained host would keep an address nothing is using reachable (issue #1117).
	target, err := containment.TargetFor(cfg.ServerURL, cfg.Proxy.ProxyFunc())
	if err != nil {
		logger.WarnContext(context.Background(), "network containment disabled: no lifeline target", "err", err)
		return nil, base
	}
	mgr := containment.New(containment.Options{Target: target, Send: send, Logger: logger})
	// Before anything dials: an agent enrolling from scratch on a contained host has no other way to learn the lifeline, since the
	// extension's status arrives on a receiver loop that starts after enrollment (issue #1065).
	mgr.Seed(statePath)
	return mgr, mgr.DialContext(base)
}

// controlDialOptions routes the control channel through dial when there is a containment manager. The target is passthrough so the dial
// receives the server's name rather than addresses gRPC resolved itself, which it could not do on a contained host.
//
// A proxied server takes the same route, tunnelling through the proxy here rather than leaving it to gRPC (issue #1064). gRPC's own
// proxy support resolves the proxy's NAME with the system resolver, and on a contained host the resolver answers nothing, so the
// control channel could not reconnect while contained even though the lifeline allows the proxy's addresses and the agent's HTTP
// transport was reaching it through them. A custom dialer replaces gRPC's proxy support rather than adding to it, so a dialer that
// tunnels is the only way to have both.
//
// Without a containment manager nothing is wrapped and gRPC dials as it always did, proxy support included.
func controlDialOptions(cfg *config.Config, target string, mgr *containment.Manager, dial dialFunc,
	proxyTLS *tls.Config) (string, []grpc.DialOption) {
	if mgr == nil {
		return target, nil
	}
	// The agent's own proxy, from its own configuration. Taken from cfg rather than passed in, so there is ONE answer to which
	// proxy the agent uses and the control channel cannot end up on a different one from its uploads (issue #1117).
	proxyURL := serverProxy(cfg.ServerURL, cfg.Proxy.ProxyFunc())
	if proxyURL != nil && !tunnelable(proxyURL) {
		// A proxy this build does not speak keeps gRPC's own dialing, which is what every proxied server had before this change:
		// the channel still cannot reconnect while the host is contained, and commands arrive by polling. Taking the dial over
		// without speaking the protocol would be worse than that, not better, since an unsupported scheme would be sent a request
		// it cannot parse, carrying the credentials the operator configured on it.
		return target, nil
	}
	return "passthrough:///" + target, []grpc.DialOption{
		grpc.WithContextDialer(controlDial(dial, proxyURL, mgr.Target().Address(), proxyTLS)),
	}
}

// tunnelable reports whether this build can establish a tunnel through the proxy: an HTTP or HTTPS proxy speaking CONNECT, or a
// SOCKS5 proxy speaking its own handshake (issues #1064, #1110).
//
// A scheme is opted IN rather than ruled out: net/http hands back whatever an operator put in the environment, `ftp://proxy`
// included, so a default branch would eventually be handed a scheme nobody considered, and would write the operator's proxy
// credentials into a protocol that cannot parse them.
func tunnelable(proxyURL *url.URL) bool {
	switch proxyURL.Scheme {
	case "http", "https", "socks5", "socks5h":
		return true
	default:
		return false
	}
}

// controlDial is the dialer gRPC is handed: straight through dial for a direct server, and a tunnel for a proxied one. Named rather
// than inline so a test can drive the choice it makes, which is the whole of the wiring.
//
// proxyAddr comes from the containment manager's own target rather than from the proxy URL, because the pin is matched by address.
// Composing it here from the URL would mean two places deciding a scheme's default port, and a disagreement would dial unpinned,
// which on a contained host is a dial that cannot succeed. The manager's target IS the proxy whenever one is configured.
func controlDial(dial dialFunc, proxyURL *url.URL, proxyAddr string,
	proxyTLS *tls.Config) func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		if proxyURL == nil {
			return dial(ctx, "tcp", addr)
		}
		return dialThroughProxy(ctx, dial, proxyURL, proxyAddr, addr, proxyTLS)
	}
}

// serverProxy returns the proxy the server URL goes through, or nil for a direct connection.
func serverProxy(serverURL string, proxy func(*http.Request) (*url.URL, error)) *url.URL {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil
	}
	p, err := proxy(&http.Request{URL: u})
	if err != nil {
		return nil
	}
	return p
}

// dialThroughProxy opens a tunnel to addr through proxyURL and returns the tunnelled connection, which gRPC then runs TLS over.
//
// The dial to the proxy goes through dial, which is the containment manager's, so on a contained host it reaches the proxy's pinned
// lifeline addresses instead of resolving its name. That is the whole point: the proxy's name is what could not be resolved.
func dialThroughProxy(ctx context.Context, dial dialFunc, proxyURL *url.URL, proxyAddr, addr string,
	proxyTLS *tls.Config) (net.Conn, error) {
	// SOCKS5 is a handshake rather than a request, and the library speaks it. The destination is handed over as a NAME, which is
	// socks5h behaviour, for both schemes: a contained host cannot resolve, so resolving locally first (plain socks5) is the one
	// thing that certainly fails there, and it is the failure this change exists to remove.
	if proxyURL.Scheme == "socks5" || proxyURL.Scheme == "socks5h" {
		return dialThroughSOCKS5(ctx, dial, proxyURL, proxyAddr, addr)
	}
	conn, err := dial(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyURL.Host, err)
	}
	// An HTTPS proxy is spoken to over TLS before ANY bytes are written, including the CONNECT that carries the operator's Basic
	// credentials. Writing that in the clear to a proxy the operator configured as https is the failure worth most avoiding here.
	if proxyURL.Scheme == "https" {
		if conn, err = handshakeWithProxy(ctx, conn, proxyURL, proxyTLS); err != nil {
			return nil, err
		}
	}
	buffered, err := connectThrough(ctx, conn, proxyURL, addr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	// The reader that read the response is kept, not discarded. Reading the response needs buffering, and a buffered reader takes
	// whatever the socket had ready, which can include the first bytes of the tunnel itself. Dropping the reader would drop those
	// bytes silently, and silently is the worst of it: the channel would hang rather than fail, on a path that runs only while a
	// host is contained.
	return &bufferedConn{Conn: conn, reader: buffered}, nil
}

// bufferedConn reads through the reader left over from the CONNECT exchange, and is otherwise the connection underneath.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// connectThrough performs the CONNECT exchange on an open proxy connection, and returns the reader it used, which may hold bytes
// belonging to the tunnel.
//
// The deadline comes from ctx and is cleared afterwards, so a slow or silent proxy fails this dial instead of hanging the control
// channel, and the deadline does not then apply to the long-lived stream that runs over the same connection.
func connectThrough(ctx context.Context, conn net.Conn, proxyURL *url.URL, addr string) (*bufio.Reader, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set proxy connect deadline: %w", err)
		}
	}
	// A deadline covers a proxy that goes quiet, and nothing covers a caller that gives up: a cancelled context does not interrupt a
	// read that has already begun, so a dial the control channel abandoned would sit here until the socket itself failed, holding a
	// connection nobody is waiting for. Setting the deadline into the past is what unblocks it.
	exchanged, watched := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watched)
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-exchanged:
		}
	}()
	// The watcher is stopped and WAITED FOR before the deadline is cleared. Clearing it first would leave a cancellation that landed
	// during the exchange free to stamp a past deadline on a connection about to be returned as good, which would kill the stream
	// that runs over it for reasons nothing in the log would explain.
	defer func() {
		close(exchanged)
		<-watched
		_ = conn.SetDeadline(time.Time{})
	}()
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	// From the proxy URL's own user info, which is where an operator configuring HTTP_PROXY puts it. http.Transport does the same
	// for its CONNECT, so a proxy that authenticates the agent's HTTP traffic authenticates this the same way.
	if user := proxyURL.User; user != nil {
		password, _ := user.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(user.Username()+":"+password)))
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("write CONNECT to proxy %s: %w", proxyURL.Host, err)
	}
	// The reader is returned rather than dropped: it has read as much as the socket had ready, which can include bytes the tunnel
	// carries, and those belong to the caller.
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT response from proxy %s: %w", proxyURL.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy %s refused CONNECT to %s: %s", proxyURL.Host, addr, resp.Status)
	}
	return reader, nil
}

// pinnedDialer hands the SOCKS5 library a way to reach the proxy that does not resolve its name.
//
// It ignores the address it is asked for and dials the manager's pinned proxy address instead. That looks wrong in isolation and
// is the point: the library is told the proxy is at that address, so the only address it ever asks for IS that one, and on a
// contained host the name behind it cannot be resolved. Going through dial is what puts the connection on the lifeline.
type pinnedDialer struct {
	dial dialFunc
	addr string
}

func (d pinnedDialer) Dial(network, _ string) (net.Conn, error) {
	return d.dial(context.Background(), network, d.addr)
}

func (d pinnedDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return d.dial(ctx, network, d.addr)
}

// dialThroughSOCKS5 opens a tunnel to addr through a SOCKS5 proxy.
//
// The handshake is x/net/proxy's rather than hand-written: a SOCKS5 client is a small protocol that is easy to get subtly wrong,
// and the wrong version of it in an agent that runs as root is not worth the lines saved.
func dialThroughSOCKS5(ctx context.Context, dial dialFunc, proxyURL *url.URL, proxyAddr, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if user := proxyURL.User; user != nil {
		password, _ := user.Password()
		auth = &proxy.Auth{User: user.Username(), Password: password}
	}
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, pinnedDialer{dial: dial, addr: proxyAddr})
	if err != nil {
		return nil, fmt.Errorf("configure SOCKS5 proxy %s: %w", proxyURL.Host, err)
	}
	// Asserted rather than assumed: without DialContext the dial would ignore the caller's deadline and cancellation, and the
	// control channel would be left holding a dial nobody is waiting for. x/net/proxy's SOCKS5 dialer implements it.
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS5 proxy %s: dialer does not support contexts", proxyURL.Host)
	}
	conn, err := contextDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 proxy %s to %s: %w", proxyURL.Host, addr, err)
	}
	return conn, nil
}

// handshakeWithProxy runs TLS to an https proxy on an already-open connection, returning the TLS connection the CONNECT then goes
// over. The original connection is closed on failure, so the caller has nothing left to clean up.
//
// The configuration is the agent's own, cloned, with only ServerName set. That is deliberate rather than convenient: net/http
// applies exactly this policy to an https proxy for the agent's uploads and polling, so a proxy certificate those accept is one
// this accepts. A stricter configuration here would fail ONLY the control channel while everything else kept working, which
// presents as the bug this is meant to fix and would be diagnosed as one.
func handshakeWithProxy(ctx context.Context, conn net.Conn, proxyURL *url.URL, proxyTLS *tls.Config) (net.Conn, error) {
	// Cloned rather than mutated: the caller's configuration is the agent's own, shared with its HTTP transport, and setting
	// ServerName on it would point every later handshake at the proxy. No nil fallback, because an https proxy without a TLS
	// policy is not a state any caller produces: main builds one before the dial and the scheme dispatch above is the only way in.
	cfg := proxyTLS.Clone()
	// The name the certificate is checked against is the PROXY's, not the server's. Without this the handshake is verified against
	// whatever ServerName the agent's own configuration carried, which is the server it is tunnelling to.
	cfg.ServerName = proxyURL.Hostname()
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("TLS handshake with proxy %s: %w", proxyURL.Host, err)
	}
	return tlsConn, nil
}
