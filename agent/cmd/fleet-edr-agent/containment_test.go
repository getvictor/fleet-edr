package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/agent/config"
	"github.com/fleetdm/edr/agent/containment"
	"github.com/fleetdm/edr/agent/health"
	"github.com/fleetdm/edr/agent/receiver"
)

func TestNewContainment(t *testing.T) {
	t.Parallel()
	var sent atomic.Int32
	send := func([]byte) error {
		sent.Add(1)
		return nil
	}
	cfg := &config.Config{ServerURL: "https://edr.example.com:8443", NetXPCService: "group.com.fleetdm.edr.networkextension"}

	var dialed []string
	record := func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("recorded")
	}

	mgr, dial := newContainment(cfg, send, record, slog.Default(), "")
	require.NotNil(t, dial)
	if runtime.GOOS != "darwin" {
		assert.Nil(t, mgr, "only macOS has a network extension to contain with")
		return
	}
	require.NotNil(t, mgr)

	noNE, _ := newContainment(&config.Config{ServerURL: cfg.ServerURL}, send, record, slog.Default(), "")
	assert.Nil(t, noNE, "an agent without the network extension service cannot contain")
	noTarget, _ := newContainment(&config.Config{ServerURL: "https:///", NetXPCService: cfg.NetXPCService}, send, record, slog.Default(), "")
	assert.Nil(t, noTarget, "a server URL without a host yields no lifeline target")

	// The dial goes through the manager. A non-canonical IPv6 literal tells a pinned dial from an unpinned one without a lookup: the
	// lifeline address is its canonical form.
	literal := &config.Config{ServerURL: "https://[2001:0db8::0001]:8443", NetXPCService: cfg.NetXPCService}
	literalMgr, literalDial := newContainment(literal, send, record, slog.Default(), "")
	require.NotNil(t, literalMgr)
	// The refresh worker, which cmd/main starts alongside the manager: a status asks it to refresh rather than refreshing on the
	// caller, so the pin this dial depends on is set by the worker.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go literalMgr.Run(ctx)
	literalMgr.Observe(ctx, containment.Status{Contained: true, Version: 1, Applied: true})
	// The dial itself is what this waits on. A send is recorded from inside the send, before the refresh records what it sent, so
	// waiting for the send would leave the dial free to run by name in that window. The canonical form is the pin: an unpinned dial
	// passes the literal through as written.
	require.Eventually(t, func() bool {
		dialed = nil
		_, _ = literalDial(ctx, "tcp", "[2001:0db8::0001]:8443")
		return len(dialed) == 1 && dialed[0] == "[2001:db8::1]:8443"
	}, 5*time.Second, 10*time.Millisecond, "the worker pins the lifeline, and the dial follows it")
}

// staticResolver answers every lookup with the same addresses.
type staticResolver []netip.Addr

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r, nil
}

func TestControlDialOptions(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{ServerURL: "https://edr.example.com:8443"}
	mgr := containment.New(containment.Options{
		Target: containment.Target{Host: "edr.example.com", Port: 8443},
		Send:   func([]byte) error { return nil },
	})
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") }
	direct := func(*http.Request) (*url.URL, error) { return nil, nil }
	proxied := func(*http.Request) (*url.URL, error) { return url.Parse("http://proxy.corp:3128") }

	target, opts := controlDialOptions(cfg, "edr.example.com:8443", nil, dial, direct, nil)
	assert.Equal(t, "edr.example.com:8443", target, "no manager: gRPC dials as before")
	assert.Empty(t, opts)

	target, opts = controlDialOptions(cfg, "edr.example.com:8443", mgr, dial, direct, nil)
	assert.Equal(t, "passthrough:///edr.example.com:8443", target, "the dial receives the server's name, not addresses gRPC resolved")
	assert.Len(t, opts, 1)

	// A proxied server is tunnelled here rather than by gRPC (issue #1064). gRPC's own proxy support would resolve the proxy's NAME,
	// which a contained host cannot do, so the control channel could not reconnect while contained.
	target, opts = controlDialOptions(cfg, "edr.example.com:8443", mgr, dial, proxied, nil)
	assert.Equal(t, "passthrough:///edr.example.com:8443", target, "gRPC must not resolve anything, proxy or server")
	assert.Len(t, opts, 1)
}

// eventConnector is a receiver.Connector that delivers a fixed list of events once connected and then stays open.
type eventConnector struct {
	events chan receiver.Event
	errs   chan int
}

func newEventConnector(events ...[]byte) *eventConnector {
	c := &eventConnector{events: make(chan receiver.Event, len(events)), errs: make(chan int)}
	for _, e := range events {
		c.events <- receiver.Event{Data: e}
	}
	return c
}

func (c *eventConnector) Connect() error                        { return nil }
func (c *eventConnector) Disconnect()                           {}
func (c *eventConnector) Events() <-chan receiver.Event         { return c.events }
func (c *eventConnector) Errors() <-chan int                    { return c.errs }
func (c *eventConnector) Ping(time.Duration) error              { return nil }
func (c *eventConnector) SendApplicationControl([]byte) error   { return nil }
func (c *eventConnector) SendWatchedPaths([]byte) error         { return nil }
func (c *eventConnector) SendNetworkContainment(p []byte) error { return nil }

// spec:agent-command-executor/the-lifeline-is-kept-current-while-contained/containment-status-is-not-uploaded
//
// The network extension's containment status reaches the manager and is never uploaded; telemetry beside it still is.
func TestReceiverLoop_ContainmentStatusIsConsumedNotUploaded(t *testing.T) {
	t.Parallel()
	mgr := containment.New(containment.Options{
		Target:   containment.Target{Host: "edr.test", Port: 8089},
		Send:     func([]byte) error { return nil },
		Resolver: staticResolver{netip.MustParseAddr("192.168.64.1")},
	})
	status := []byte(`{"event_type":"ne_containment_status","payload":{"contained":true,"version":3,"epoch":100,"applied":true}}`)
	telemetry := []byte(`{"event_type":"network_connect","payload":{}}`)
	var mu sync.Mutex
	var uploaded [][]byte
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// The refresh worker, which cmd/main starts beside the receiver loop: a status asks it to refresh rather than refreshing on the
	// receiver's event goroutine, so without it nothing resolves or sends.
	go mgr.Run(ctx)
	go startReceiverLoop(ctx, receiverLoopParams{
		logger:           slog.Default(),
		serviceLabel:     "test-ne",
		containment:      mgr,
		providerLiveness: true,
		connectorFactory: func() receiver.Connector { return newEventConnector(status, telemetry) },
		enqueue: func(_ context.Context, data []byte) error {
			mu.Lock()
			defer mu.Unlock()
			uploaded = append(uploaded, data)
			return nil
		},
	})

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(uploaded) == 1
	}, 2*time.Second, 10*time.Millisecond)
	mu.Lock()
	assert.Equal(t, [][]byte{telemetry}, uploaded, "only the telemetry is uploaded")
	mu.Unlock()
	// The manager adopted the contained state, so a dial to the lifeline target is pinned.
	var dialed string
	dial := mgr.DialContext(func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = addr
		return nil, errors.New("recorded")
	})
	require.Eventually(t, func() bool {
		_, _ = dial(t.Context(), "tcp", "edr.test:8089")
		return dialed == "192.168.64.1:8089"
	}, 2*time.Second, 10*time.Millisecond)
}

// A network extension loop with no manager, as on a host whose server URL yields no lifeline target, still keeps the extension's
// containment status out of the upload queue.
func TestReceiverLoop_ContainmentStatusIsDroppedWithoutAManager(t *testing.T) {
	t.Parallel()
	status := []byte(`{"event_type":"ne_containment_status","payload":{"contained":true,"version":3,"epoch":100,"applied":true}}`)
	telemetry := []byte(`{"event_type":"network_connect","payload":{}}`)
	var mu sync.Mutex
	var uploaded [][]byte
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go startReceiverLoop(ctx, receiverLoopParams{
		logger:           slog.Default(),
		serviceLabel:     "test-ne",
		providerLiveness: true,
		connectorFactory: func() receiver.Connector { return newEventConnector(status, telemetry) },
		enqueue: func(_ context.Context, data []byte) error {
			mu.Lock()
			defer mu.Unlock()
			uploaded = append(uploaded, data)
			return nil
		},
	})
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(uploaded) == 1
	}, 2*time.Second, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, [][]byte{telemetry}, uploaded)
}

// When the connection to the network extension drops and returns, the status the extension sends on the new connection sends the
// lifeline again: a send over the dropped connection may never have arrived.
func TestReceiverLoop_AReconnectSendsTheLifelineAgain(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	sends := 0
	mgr := containment.New(containment.Options{
		Target: containment.Target{Host: "edr.test", Port: 8089},
		Send: func([]byte) error {
			mu.Lock()
			defer mu.Unlock()
			sends++
			return nil
		},
		Resolver: staticResolver{netip.MustParseAddr("192.168.64.1")},
	})
	sent := func() int {
		mu.Lock()
		defer mu.Unlock()
		return sends
	}
	status := []byte(`{"event_type":"ne_containment_status","payload":{"contained":true,"version":3,"epoch":100,"applied":true}}`)
	connectors := make(chan *eventConnector, 4)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// The refresh worker, which cmd/main starts beside the receiver loop: a status asks it to refresh rather than refreshing on the
	// receiver's event goroutine, so without it nothing resolves or sends.
	go mgr.Run(ctx)
	go startReceiverLoop(ctx, receiverLoopParams{
		logger:           slog.Default(),
		serviceLabel:     "test-ne",
		containment:      mgr,
		providerLiveness: true,
		dispatcher:       receiver.NewDispatcher(),
		connectorFactory: func() receiver.Connector {
			c := newEventConnector(status)
			connectors <- c
			return c
		},
		enqueue: func(context.Context, []byte) error { return nil },
	})
	first := <-connectors
	require.Eventually(t, func() bool { return sent() == 1 }, 2*time.Second, 10*time.Millisecond)
	first.errs <- 1
	require.Eventually(t, func() bool { return sent() == 2 }, 5*time.Second, 10*time.Millisecond)
}

// The provider-liveness report shares the network extension loop's single type peek with containment status: it is recorded to health
// and never uploaded, while telemetry beside it still is.
func TestReceiverLoop_ProviderStatusIsRecordedNotUploaded(t *testing.T) {
	t.Parallel()
	registry := health.NewRegistry()
	registry.Register(health.ComponentNetworkExtension, "Network extension")
	status := []byte(`{"event_type":"ne_provider_status","payload":{"providers":{"content_filter":"running","dns_proxy":"running"}}}`)
	telemetry := []byte(`{"event_type":"network_connect","payload":{}}`)
	var mu sync.Mutex
	var uploaded [][]byte
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go startReceiverLoop(ctx, receiverLoopParams{
		logger:           slog.Default(),
		serviceLabel:     "test-ne",
		health:           registry,
		component:        health.ComponentNetworkExtension,
		providerLiveness: true,
		connectorFactory: func() receiver.Connector { return newEventConnector(status, telemetry) },
		enqueue: func(_ context.Context, data []byte) error {
			mu.Lock()
			defer mu.Unlock()
			uploaded = append(uploaded, data)
			return nil
		},
	})
	require.Eventually(t, func() bool { return len(registry.Snapshot()) == 3 }, 2*time.Second, 10*time.Millisecond,
		"the network extension and its two providers")
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(uploaded) == 1
	}, 2*time.Second, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, [][]byte{telemetry}, uploaded)
}

// The wiring, not the manager: an agent built on a contained host must dial the lifeline the extension persisted, because the enroll
// that follows cannot resolve the server's name (issue #1065). Deleting the Seed call in newContainment fails here.
func TestNewContainment_SeedsFromTheExtensionsPersistedState(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "darwin" {
		t.Skip("only macOS builds a containment manager")
	}
	path := filepath.Join(t.TempDir(), "network-containment.json")
	doc := `{"version":3,"epoch":100,"contained":true,` +
		`"server":{"port":8443,"addresses":["203.0.113.7"],"names":["edr.example.com"]}}`
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

	var dialed []string
	record := func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("recorded")
	}
	cfg := &config.Config{ServerURL: "https://edr.example.com:8443", NetXPCService: "group.com.fleetdm.edr.networkextension"}

	_, dial := newContainment(cfg, func([]byte) error { return nil }, record, slog.Default(), path)
	_, _ = dial(t.Context(), "tcp", "edr.example.com:8443")

	assert.Equal(t, []string{"203.0.113.7:8443"}, dialed, "the enroll dials the lifeline rather than resolving the name")
}
