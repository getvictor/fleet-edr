package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"time"

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
	target, err := containment.TargetFor(cfg.ServerURL, http.ProxyFromEnvironment)
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
	proxy func(*http.Request) (*url.URL, error)) (string, []grpc.DialOption) {
	if mgr == nil {
		return target, nil
	}
	proxyURL := serverProxy(cfg.ServerURL, proxy)
	return "passthrough:///" + target, []grpc.DialOption{grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		if proxyURL == nil {
			return dial(ctx, "tcp", addr)
		}
		return dialThroughProxy(ctx, dial, proxyURL, addr)
	})}
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
func dialThroughProxy(ctx context.Context, dial dialFunc, proxyURL *url.URL, addr string) (net.Conn, error) {
	conn, err := dial(ctx, "tcp", proxyAddress(proxyURL))
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyURL.Host, err)
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
		defer func() { _ = conn.SetDeadline(time.Time{}) }()
	}
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

// proxyAddress is the proxy's host and port, defaulted by scheme the way net/http defaults it, since a proxy URL is commonly written
// without one.
func proxyAddress(proxyURL *url.URL) string {
	if proxyURL.Port() != "" {
		return proxyURL.Host
	}
	if proxyURL.Scheme == "https" {
		return net.JoinHostPort(proxyURL.Hostname(), "443")
	}
	return net.JoinHostPort(proxyURL.Hostname(), "80")
}
