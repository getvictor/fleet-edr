package main

import (
	"context"
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
func newContainment(cfg *config.Config, send func([]byte) error, base dialFunc, logger *slog.Logger) (*containment.Manager, dialFunc) {
	if runtime.GOOS != "darwin" || cfg.NetXPCService == "" {
		return nil, base
	}
	target, err := containment.TargetFor(cfg.ServerURL, http.ProxyFromEnvironment)
	if err != nil {
		logger.WarnContext(context.Background(), "network containment disabled: no lifeline target", "err", err)
		return nil, base
	}
	mgr := containment.New(containment.Options{Target: target, Send: send, Logger: logger})
	return mgr, mgr.DialContext(base)
}

// controlDialOptions routes the control channel through dial when there is a containment manager. The target is passthrough so the dial
// receives the server's name rather than addresses gRPC resolved itself, which it could not do on a contained host. A proxied server
// keeps gRPC's own dialing: a custom dialer replaces gRPC's proxy support.
func controlDialOptions(cfg *config.Config, target string, mgr *containment.Manager, dial dialFunc,
	proxy func(*http.Request) (*url.URL, error)) (string, []grpc.DialOption) {
	if mgr == nil || serverIsProxied(cfg.ServerURL, proxy) {
		return target, nil
	}
	return "passthrough:///" + target, []grpc.DialOption{grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		return dial(ctx, "tcp", addr)
	})}
}

func serverIsProxied(serverURL string, proxy func(*http.Request) (*url.URL, error)) bool {
	u, err := url.Parse(serverURL)
	if err != nil {
		return false
	}
	p, err := proxy(&http.Request{URL: u})
	return err == nil && p != nil
}
