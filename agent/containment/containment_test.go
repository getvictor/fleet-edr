package containment

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeResolver answers lookups from a settable list and counts them.
type fakeResolver struct {
	mu    sync.Mutex
	addrs []netip.Addr
	err   error
	calls int
}

func (f *fakeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.addrs, f.err
}

func (f *fakeResolver) lookups() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeResolver) set(addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs = nil
	for _, a := range addrs {
		f.addrs = append(f.addrs, netip.MustParseAddr(a))
	}
}

// fakeExtension records every document sent and, when respond is set, answers each with the status it returns.
type fakeExtension struct {
	mu      sync.Mutex
	docs    []document
	err     error
	respond func(document) *Status
	mgr     *Manager
}

func (f *fakeExtension) send(payload []byte) error {
	var d document
	if err := json.Unmarshal(payload, &d); err != nil {
		return err
	}
	f.mu.Lock()
	f.docs = append(f.docs, d)
	respond, mgr, err := f.respond, f.mgr, f.err
	f.mu.Unlock()
	if err != nil {
		return err
	}
	if respond != nil {
		if s := respond(d); s != nil {
			go mgr.Observe(context.Background(), *s)
		}
	}
	return nil
}

func (f *fakeExtension) sent() []document {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]document(nil), f.docs...)
}

// applies answers every document the way a healthy extension does: it holds and applies what it was sent.
func applies(d document) *Status {
	return &Status{Contained: d.Contained, Version: d.Version, Epoch: d.Epoch, Applied: true}
}

func newTestManager(t *testing.T, target Target, respond func(document) *Status) (*Manager, *fakeExtension, *fakeResolver) {
	t.Helper()
	res := &fakeResolver{}
	ext := &fakeExtension{respond: respond}
	m := New(Options{Target: target, Send: ext.send, Resolver: res, ApplyTimeout: 500 * time.Millisecond, RefreshInterval: time.Hour})
	ext.mgr = m
	return m, ext, res
}

var serverTarget = Target{Host: "edr.example.com", Port: 8443}

func TestTargetFor(t *testing.T) {
	t.Parallel()
	proxy := func(*http.Request) (*url.URL, error) { return url.Parse("http://proxy.corp:3128") }
	cases := []struct {
		name    string
		url     string
		proxy   func(*http.Request) (*url.URL, error)
		want    Target
		wantErr bool
	}{
		{"https defaults to 443", "https://edr.example.com", nil, Target{"edr.example.com", 443}, false},
		{"an explicit port", "https://edr.example.com:8443/", nil, Target{"edr.example.com", 8443}, false},
		{"http defaults to 80", "http://10.0.0.5", nil, Target{"10.0.0.5", 80}, false},
		{"a proxy is the target", "https://edr.example.com", proxy, Target{"proxy.corp", 3128}, false},
		{"no proxy for this URL", "https://edr.example.com", func(*http.Request) (*url.URL, error) { return nil, nil },
			Target{"edr.example.com", 443}, false},
		{"no host", "https:///path", nil, Target{}, true},
		{"a bad port", "https://edr.example.com:port", nil, Target{}, true},
		{"a port above 65535", "https://edr.example.com:65536", nil, Target{}, true},
		{"port zero", "https://edr.example.com:0", nil, Target{}, true},
		{"the highest port", "https://edr.example.com:65535", nil, Target{"edr.example.com", 65535}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := TargetFor(tc.url, tc.proxy)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// spec:agent-command-executor/set-network-containment-command/the-extension-confirms-the-containment
func TestApply_ContainSendsTheLifelineAndWaitsForTheExtension(t *testing.T) {
	t.Parallel()
	m, ext, res := newTestManager(t, serverTarget, applies)
	// Duplicates, a v4-mapped address and the unspecified address are dropped.
	res.set("203.0.113.7", "::ffff:203.0.113.7", "2001:db8::7", "0.0.0.0")

	result, err := m.Apply(t.Context(), []byte(`{"version":3,"epoch":100,"contained":true}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"version":3,"contained":true,"applied":true,"lifeline":["203.0.113.7","2001:db8::7"]}`, string(result))
	require.Len(t, ext.sent(), 1)
	assert.Equal(t, document{Version: 3, Epoch: 100, Contained: true,
		Server: &server{Port: 8443, Addresses: []string{"203.0.113.7", "2001:db8::7"}, Names: []string{"edr.example.com"}}}, ext.sent()[0])
}

func TestApply_TheDocumentWireShape(t *testing.T) {
	t.Parallel()
	doc := document{Version: 3, Epoch: 100, Contained: true,
		Server: &server{Port: 8443, Addresses: []string{"203.0.113.7"}, Names: []string{"edr.example.com"}}}
	body, err := json.Marshal(doc)
	require.NoError(t, err)
	want := `{"version":3,"epoch":100,"contained":true,` +
		`"server":{"port":8443,"addresses":["203.0.113.7"],"names":["edr.example.com"]}}`
	assert.JSONEq(t, want, string(body))
	release, err := json.Marshal(document{Version: 4, Epoch: 100})
	require.NoError(t, err)
	assert.JSONEq(t, `{"version":4,"epoch":100,"contained":false}`, string(release), "a release carries no server")
}

func TestApply_ReleaseResolvesNothing(t *testing.T) {
	t.Parallel()
	m, ext, res := newTestManager(t, serverTarget, applies)
	result, err := m.Apply(t.Context(), []byte(`{"version":4,"epoch":100,"contained":false}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"version":4,"contained":false,"applied":true,"lifeline":[]}`, string(result))
	assert.Nil(t, ext.sent()[0].Server)
	assert.Zero(t, res.calls)
}

func TestApply_AnIPLiteralTargetNeedsNoLookup(t *testing.T) {
	t.Parallel()
	m, ext, res := newTestManager(t, Target{Host: "192.168.64.1", Port: 8089}, applies)
	_, err := m.Apply(t.Context(), []byte(`{"version":1,"contained":true}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"192.168.64.1"}, ext.sent()[0].Server.Addresses)
	assert.Empty(t, ext.sent()[0].Server.Names, "an IP literal needs no name resolved")
	assert.Zero(t, res.calls)
}

// spec:agent-command-executor/set-network-containment-command/a-containment-whose-lifeline-cannot-be-resolved-is-not-sent
// spec:agent-command-executor/set-network-containment-command/the-extension-does-not-apply-the-containment
func TestApply_Failures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		payload  string
		respond  func(document) *Status
		resolved []string
		resolve  error
		sendErr  error
		wantErr  string
		wantSent int
	}{
		{name: "invalid payload", payload: `{`, respond: applies, wantErr: "invalid payload"},
		{name: "no version", payload: `{"contained":true}`, respond: applies, wantErr: "invalid version"},
		{name: "an unresolvable lifeline is not sent", payload: `{"version":1,"contained":true}`, respond: applies,
			resolve: errors.New("no such host"), wantErr: "resolve the lifeline"},
		{name: "no usable address is not sent", payload: `{"version":1,"contained":true}`, respond: applies,
			resolved: []string{"0.0.0.0", "::"}, wantErr: "no usable addresses"},
		{name: "the extension is not connected", payload: `{"version":1,"contained":true}`, respond: applies,
			sendErr: errors.New("no connector"), wantErr: "send to the network extension", wantSent: 1},
		{name: "the extension does not answer", payload: `{"version":1,"contained":true}`, respond: func(document) *Status { return nil },
			wantErr: "did not confirm", wantSent: 1},
		{name: "the extension could not apply it", payload: `{"version":1,"contained":true}`,
			respond: func(d document) *Status {
				return &Status{Contained: true, Version: d.Version, Epoch: d.Epoch, Applied: false, Error: "content filter is not running"}
			}, wantErr: "content filter is not running", wantSent: 1},
		{name: "a pending status is waited on until the deadline", payload: `{"version":1,"contained":true}`,
			respond: func(d document) *Status { return &Status{Contained: true, Version: d.Version, Epoch: d.Epoch} },
			wantErr: "did not confirm", wantSent: 1},
		{name: "the host holds a newer state", payload: `{"version":1,"epoch":100,"contained":true}`,
			respond: func(document) *Status { return &Status{Contained: false, Version: 2, Epoch: 100, Applied: true} },
			wantErr: "superseded on the host by version 2", wantSent: 1},
		{name: "the host holds a state from a newer epoch", payload: `{"version":5,"epoch":100,"contained":true}`,
			respond: func(document) *Status { return &Status{Contained: false, Version: 1, Epoch: 101, Applied: true} },
			wantErr: "superseded on the host by version 1", wantSent: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, ext, res := newTestManager(t, serverTarget, tc.respond)
			res.set("203.0.113.7")
			if tc.resolved != nil {
				res.set(tc.resolved...)
			}
			res.err = tc.resolve
			ext.err = tc.sendErr
			_, err := m.Apply(t.Context(), []byte(tc.payload))
			require.ErrorContains(t, err, tc.wantErr)
			assert.Len(t, ext.sent(), tc.wantSent)
		})
	}
}

// spec:agent-command-executor/the-lifeline-is-kept-current-while-contained/a-restarted-agent-refreshes-the-lifeline
//
// An agent that restarts while the host is contained learns it from the extension's status and refreshes the lifeline once.
func TestObserve_AContainmentHeldAcrossARestartIsRefreshedOnce(t *testing.T) {
	t.Parallel()
	m, ext, res := newTestManager(t, serverTarget, nil)
	res.set("203.0.113.9")
	held := Status{Contained: true, Version: 3, Epoch: 100, Applied: true}

	m.Observe(t.Context(), held)
	require.Len(t, ext.sent(), 1)
	assert.Equal(t, document{Version: 3, Epoch: 100, Contained: true,
		Server: &server{Port: 8443, Addresses: []string{"203.0.113.9"}, Names: []string{"edr.example.com"}}}, ext.sent()[0])

	m.Observe(t.Context(), held)
	assert.Len(t, ext.sent(), 1, "the same status on the next connect sends nothing new")

	m.Observe(t.Context(), Status{Contained: false, Version: 4, Epoch: 100, Applied: true})
	assert.Len(t, ext.sent(), 1)
	assert.Equal(t, 1, res.lookups(), "a release reported by the extension resolves nothing")
}

// spec:agent-command-executor/the-lifeline-is-kept-current-while-contained/an-undelivered-lifeline-refresh-is-sent-again
//
// A lifeline refresh the extension did not receive is not recorded as sent, so the status the extension reports when it reconnects
// sends it again, and dials are not pinned to addresses the extension never allowed.
func TestObserve_AFailedRefreshIsSentAgainOnTheNextStatus(t *testing.T) {
	t.Parallel()
	m, ext, res := newTestManager(t, serverTarget, nil)
	res.set("203.0.113.9")
	held := Status{Contained: true, Version: 3, Epoch: 100, Applied: true}
	ext.err = errors.New("no connector")

	m.Observe(t.Context(), held)
	require.Len(t, ext.sent(), 1)
	assert.Empty(t, m.pinned("edr.example.com:8443"))

	ext.mu.Lock()
	ext.err = nil
	ext.mu.Unlock()
	m.Observe(t.Context(), held)
	require.Len(t, ext.sent(), 2, "the next status sends the lifeline again")
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.9")}, m.pinned("edr.example.com:8443"))
}

// gatedResolver blocks each lookup until release is closed, after reporting that it started. A lookup nobody waits for fails rather
// than blocking the test.
type gatedResolver struct {
	started chan struct{}
	release chan struct{}
}

func (g *gatedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	select {
	case g.started <- struct{}{}:
	case <-time.After(time.Second):
		return nil, errors.New("unexpected lookup")
	}
	<-g.release
	return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
}

// A release the extension reports while a lifeline lookup is still running is not answered with a containment document once the
// lookup returns.
func TestObserve_AReleaseDuringTheLookupSendsNothing(t *testing.T) {
	t.Parallel()
	res := &gatedResolver{started: make(chan struct{}), release: make(chan struct{})}
	ext := &fakeExtension{}
	m := New(Options{Target: serverTarget, Send: ext.send, Resolver: res, RefreshInterval: time.Hour})
	ext.mgr = m

	done := make(chan struct{})
	go func() {
		m.Observe(t.Context(), Status{Contained: true, Version: 3, Epoch: 100, Applied: true})
		close(done)
	}()
	<-res.started
	m.Observe(t.Context(), Status{Contained: false, Version: 4, Epoch: 100, Applied: true})
	close(res.release)
	<-done
	assert.Empty(t, ext.sent())
	assert.Empty(t, m.pinned("edr.example.com:8443"))
}

// A release the extension reports while a refresh is being sent leaves dials unpinned once the send returns.
func TestObserve_AReleaseDuringTheRefreshSendLeavesDialsUnpinned(t *testing.T) {
	t.Parallel()
	res := &fakeResolver{}
	res.set("203.0.113.9")
	var m *Manager
	send := func([]byte) error {
		m.Observe(context.Background(), Status{Contained: false, Version: 4, Epoch: 100, Applied: true})
		return nil
	}
	m = New(Options{Target: serverTarget, Send: send, Resolver: res, RefreshInterval: time.Hour})
	m.Observe(t.Context(), Status{Contained: true, Version: 3, Epoch: 100, Applied: true})
	assert.Empty(t, m.pinned("edr.example.com:8443"))
}

// A status at the command's version from another epoch is not the command's confirmation: the extension holds some other state whose
// addresses the agent does not know, so the lifeline is refreshed for it rather than assumed to be the addresses the command sent.
func TestObserve_AHeldStateFromAnotherEpochIsRefreshed(t *testing.T) {
	t.Parallel()
	m, ext, res := newTestManager(t, serverTarget, func(d document) *Status {
		if d.Epoch != 100 {
			return nil
		}
		return &Status{Contained: true, Version: d.Version, Epoch: 99, Applied: true}
	})
	res.set("203.0.113.7")
	_, err := m.Apply(t.Context(), []byte(`{"version":3,"epoch":100,"contained":true}`))
	require.ErrorContains(t, err, "did not confirm")
	require.Eventually(t, func() bool { return len(ext.sent()) == 2 }, time.Second, 5*time.Millisecond)
	assert.Equal(t, int64(99), ext.sent()[1].Epoch)
	assert.Equal(t, []string{"203.0.113.7"}, ext.sent()[1].Server.Addresses)
}

func TestApply_TheLifelineIsCappedAtSixteenAddresses(t *testing.T) {
	t.Parallel()
	m, ext, res := newTestManager(t, serverTarget, applies)
	addrs := make([]string, 0, 20)
	for i := range 20 {
		addrs = append(addrs, netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}).String())
	}
	res.set(addrs...)
	_, err := m.Apply(t.Context(), []byte(`{"version":1,"contained":true}`))
	require.NoError(t, err)
	assert.Equal(t, addrs[:16], ext.sent()[0].Server.Addresses, "the extension refuses more than sixteen")
}

func TestObserve_AfterApplyTheConfirmingStatusSendsNoRefresh(t *testing.T) {
	t.Parallel()
	m, ext, res := newTestManager(t, serverTarget, applies)
	res.set("203.0.113.7")
	_, err := m.Apply(t.Context(), []byte(`{"version":3,"epoch":100,"contained":true}`))
	require.NoError(t, err)
	m.Observe(t.Context(), Status{Contained: true, Version: 3, Epoch: 100, Applied: true})
	assert.Len(t, ext.sent(), 1)
	assert.Equal(t, 1, res.lookups(), "the addresses the command sent are the ones the extension holds, so nothing is resolved again")
}

// spec:agent-command-executor/the-lifeline-is-kept-current-while-contained/a-moved-server-address-reaches-the-extension
func TestRun_RefreshesTheLifelineWhenTheAddressesMove(t *testing.T) {
	t.Parallel()
	res := &fakeResolver{}
	ext := &fakeExtension{}
	m := New(Options{Target: serverTarget, Send: ext.send, Resolver: res, RefreshInterval: 10 * time.Millisecond})
	ext.mgr = m
	res.set("203.0.113.7")
	m.Observe(t.Context(), Status{Contained: true, Version: 3, Epoch: 100, Applied: true})
	require.Len(t, ext.sent(), 1)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go m.Run(ctx)
	time.Sleep(60 * time.Millisecond)
	assert.Len(t, ext.sent(), 1, "unchanged addresses are not resent")

	res.set("203.0.113.8")
	require.Eventually(t, func() bool { return len(ext.sent()) == 2 }, time.Second, 5*time.Millisecond)
	assert.Equal(t, []string{"203.0.113.8"}, ext.sent()[1].Server.Addresses)
	assert.Equal(t, int64(3), ext.sent()[1].Version, "a refresh keeps the state's version")

	m.Observe(t.Context(), Status{Contained: false, Version: 4, Epoch: 100, Applied: true})
	res.set("203.0.113.9")
	time.Sleep(60 * time.Millisecond)
	assert.Len(t, ext.sent(), 2, "a released host is not refreshed")
}

// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/contained-dials-use-the-lifeline
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/a-released-host-dials-the-server-by-name
func TestDialContext_PinsTheLifelineOnlyWhileContained(t *testing.T) {
	t.Parallel()
	m, _, res := newTestManager(t, serverTarget, applies)
	res.set("203.0.113.7", "203.0.113.8")
	var mu sync.Mutex
	var dialed []string
	base := func(_ context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		dialed = append(dialed, addr)
		if addr == "203.0.113.7:8443" {
			return nil, errors.New("unreachable")
		}
		return nil, nil
	}
	dial := m.DialContext(base)
	reset := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := dialed
		dialed = nil
		return out
	}

	_, _ = dial(t.Context(), "tcp", "edr.example.com:8443")
	assert.Equal(t, []string{"edr.example.com:8443"}, reset(), "not contained: dial by name")

	_, err := m.Apply(t.Context(), []byte(`{"version":1,"contained":true}`))
	require.NoError(t, err)
	_, err = dial(t.Context(), "tcp", "EDR.example.com:8443")
	require.NoError(t, err)
	assert.Equal(t, []string{"203.0.113.7:8443", "203.0.113.8:8443"}, reset(), "contained: each lifeline address in turn")
	m.Observe(t.Context(), Status{Contained: false, Version: 2, Error: "content filter is not running"})
	_, _ = dial(t.Context(), "tcp", "edr.example.com:8443")
	assert.Equal(t, []string{"203.0.113.7:8443", "203.0.113.8:8443"}, reset(), "a release the extension did not apply stays pinned")
	_, _ = dial(t.Context(), "tcp", "other.example.com:8443")
	assert.Equal(t, []string{"other.example.com:8443"}, reset(), "another host is dialed as asked")
	_, _ = dial(t.Context(), "tcp", "edr.example.com:443")
	assert.Equal(t, []string{"edr.example.com:443"}, reset(), "another port is dialed as asked")

	_, err = m.Apply(t.Context(), []byte(`{"version":2,"contained":false}`))
	require.NoError(t, err)
	_, _ = dial(t.Context(), "tcp", "edr.example.com:8443")
	assert.Equal(t, []string{"edr.example.com:8443"}, reset(), "released: dial by name again")

	// A containment and release this agent learns from the extension's status, as after an agent restart, pin and unpin the same way.
	m.Observe(t.Context(), Status{Contained: true, Version: 5, Epoch: 1, Applied: true})
	_, _ = dial(t.Context(), "tcp", "edr.example.com:8443")
	assert.Equal(t, []string{"203.0.113.7:8443", "203.0.113.8:8443"}, reset())
	m.Observe(t.Context(), Status{Contained: false, Version: 6, Epoch: 1, Applied: true})
	_, _ = dial(t.Context(), "tcp", "edr.example.com:8443")
	assert.Equal(t, []string{"edr.example.com:8443"}, reset(), "a release reported by the extension unpins too")
}

func TestParseStatus(t *testing.T) {
	t.Parallel()
	s, ok := ParseStatus([]byte(`{"event_type":"ne_containment_status",` +
		`"payload":{"contained":true,"version":3,"epoch":100,"applied":false,"error":"x"}}`))
	require.True(t, ok)
	assert.Equal(t, Status{Contained: true, Version: 3, Epoch: 100, Applied: false, Error: "x"}, s)

	_, ok = ParseStatus([]byte(`{"event_type":"network_connect","payload":{}}`))
	assert.False(t, ok, "telemetry is not a status")

	s, ok = ParseStatus([]byte(`{"event_type":"ne_containment_status","payload":"nope"}`))
	assert.True(t, ok, "a status that does not decode is still kept out of the upload queue")
	assert.False(t, s.Applied)
}

// The extension reports a held state as pending (not applied, no error) while it waits behind an apply in flight; the command keeps
// waiting and completes on the applied status that follows.
func TestApply_APendingStatusIsFollowedByTheApplied(t *testing.T) {
	t.Parallel()
	m, _, _ := newTestManager(t, Target{Host: "192.168.64.1", Port: 8089}, func(d document) *Status {
		pending := Status{Contained: d.Contained, Version: d.Version, Epoch: d.Epoch}
		return &pending
	})
	done := make(chan error, 1)
	go func() {
		_, err := m.Apply(t.Context(), []byte(`{"version":7,"epoch":1,"contained":true}`))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	m.Observe(t.Context(), Status{Contained: true, Version: 7, Epoch: 1, Applied: true})
	require.NoError(t, <-done)
}
