package containment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
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
		{"a SOCKS5 proxy defaults to 1080", "https://edr.example.com",
			func(*http.Request) (*url.URL, error) { return url.Parse("socks5://proxy.corp") }, Target{"proxy.corp", 1080}, false},
		{"a SOCKS5h proxy defaults to 1080", "https://edr.example.com",
			func(*http.Request) (*url.URL, error) { return url.Parse("socks5h://proxy.corp") }, Target{"proxy.corp", 1080}, false},
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

// An IP literal target is normalized like a resolved address, and one the extension would refuse is refused before anything is sent.
func TestApply_AnIPLiteralTargetIsNormalized(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, host, wantAddress, wantErr string
	}{
		{name: "a v4-mapped literal is unmapped", host: "::ffff:192.0.2.1", wantAddress: "192.0.2.1"},
		{name: "the unspecified address", host: "0.0.0.0", wantErr: "no usable addresses"},
		{name: "a scoped literal", host: "fe80::1%en0", wantErr: "no usable addresses"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, ext, _ := newTestManager(t, Target{Host: tc.host, Port: 8089}, applies)
			_, err := m.Apply(t.Context(), []byte(`{"version":1,"contained":true}`))
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				assert.Empty(t, ext.sent())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []string{tc.wantAddress}, ext.sent()[0].Server.Addresses)
		})
	}
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
		{name: "no contained", payload: `{"version":1}`, respond: applies, wantErr: "payload missing contained"},
		{name: "a null contained", payload: `{"version":1,"contained":null}`, respond: applies, wantErr: "payload missing contained"},
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
		{name: "the host holds the other state at this version", payload: `{"version":1,"epoch":100,"contained":true}`,
			respond: func(d document) *Status {
				return &Status{Contained: false, Version: d.Version, Epoch: d.Epoch, Applied: true}
			},
			wantErr: "the host holds a different state at version 1", wantSent: 1},
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

func TestDecodeStatus(t *testing.T) {
	t.Parallel()
	undecodable := Status{Error: "undecodable containment status"}
	cases := []struct {
		name string
		data string
		want Status
	}{
		{"a status", `{"event_type":"ne_containment_status","payload":{"contained":true,"version":3,"epoch":100,"applied":false,"error":"x"}}`,
			Status{Contained: true, Version: 3, Epoch: 100, Error: "x"}},
		{"not JSON", `{`, undecodable},
		{"a payload that does not decode", `{"event_type":"ne_containment_status","payload":"nope"}`, undecodable},
		{"a status naming no state adopts nothing", `{"event_type":"ne_containment_status","payload":{"applied":true}}`, undecodable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, DecodeStatus([]byte(tc.data)))
		})
	}
}

// FuzzDecodeStatus feeds the network extension's control messages to the status decoder: it must not panic, and what it returns either
// names a state or is marked undecodable and not applied.
func FuzzDecodeStatus(f *testing.F) {
	f.Add([]byte(`{"event_type":"ne_containment_status","payload":{"contained":true,"version":3,"epoch":100,"applied":true}}`))
	f.Add([]byte(`{"event_type":"ne_containment_status","payload":{"applied":true}}`))
	f.Add([]byte(`{"event_type":"network_connect"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if s := DecodeStatus(data); s.Version <= 0 && (s.Error == "" || s.Applied) {
			t.Fatalf("a status naming no state was not marked undecodable: %+v", s)
		}
	})
}

// FuzzApply feeds set_network_containment payloads from the server to Apply: it must not panic, and a payload it cannot validate is
// refused before anything is sent to the extension.
func FuzzApply(f *testing.F) {
	f.Add([]byte(`{"version":3,"epoch":100,"contained":true}`))
	f.Add([]byte(`{"version":3}`))
	f.Add([]byte(`{"version":-1,"contained":false}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		sent := 0
		m := New(Options{Target: serverTarget, Resolver: &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.7")}},
			Send: func([]byte) error { sent++; return errors.New("not connected") }})
		_, err := m.Apply(t.Context(), payload)
		if err == nil {
			t.Fatalf("an unconnected extension confirmed %q", payload)
		}
		var fields struct {
			Version   int64 `json:"version"`
			Contained *bool `json:"contained"`
		}
		if json.Unmarshal(payload, &fields) != nil || fields.Version <= 0 || fields.Contained == nil {
			if sent != 0 {
				t.Fatalf("sent an invalid payload %q", payload)
			}
		}
	})
}

// TestWireTypesRoundTrip is the round trip the testing-strategy matrix requires for new wire types: the command payload, the
// extension's status and the document the agent sends it.
func TestWireTypesRoundTrip(t *testing.T) {
	t.Parallel()
	roundTrip := func(rt *rapid.T, in, out any) {
		body, err := json.Marshal(in)
		require.NoError(rt, err)
		require.NoError(rt, json.Unmarshal(body, out))
	}
	t.Run("command", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			in := Command{
				Version: rapid.Int64().Draw(rt, "version"), Epoch: rapid.Int64().Draw(rt, "epoch"), Contained: rapid.Bool().Draw(rt, "contained"),
			}
			var out Command
			roundTrip(rt, in, &out)
			assert.Equal(rt, in, out)
		})
	})
	t.Run("status", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			in := Status{Contained: rapid.Bool().Draw(rt, "contained"), Version: rapid.Int64().Draw(rt, "version"),
				Epoch: rapid.Int64().Draw(rt, "epoch"), Applied: rapid.Bool().Draw(rt, "applied"), Error: rapid.String().Draw(rt, "error")}
			var out Status
			roundTrip(rt, in, &out)
			assert.Equal(rt, in, out)
		})
	})
	t.Run("document", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			in := document{
				Version: rapid.Int64().Draw(rt, "version"), Epoch: rapid.Int64().Draw(rt, "epoch"), Contained: rapid.Bool().Draw(rt, "contained"),
			}
			if rapid.Bool().Draw(rt, "has_server") {
				in.Server = &server{Port: rapid.IntRange(1, 65535).Draw(rt, "port"),
					Addresses: rapid.SliceOfN(rapid.String(), 1, 16).Draw(rt, "addresses")}
				if rapid.Bool().Draw(rt, "has_name") {
					in.Server.Names = []string{rapid.StringN(1, 253, -1).Draw(rt, "name")}
				}
			}
			var out document
			roundTrip(rt, in, &out)
			assert.Equal(rt, in, out)
		})
	})
}

// Commands run one at a time: the second is not sent to the extension until the first has its answer, so each confirmation adopts the
// addresses its own command sent.
func TestApply_CommandsRunOneAtATime(t *testing.T) {
	t.Parallel()
	m, ext, res := newTestManager(t, serverTarget, func(d document) *Status {
		if d.Version == 1 {
			return nil
		}
		return applies(d)
	})
	res.set("203.0.113.7")
	first := make(chan error, 1)
	go func() {
		_, err := m.Apply(t.Context(), []byte(`{"version":1,"epoch":100,"contained":true}`))
		first <- err
	}()
	require.Eventually(t, func() bool { return len(ext.sent()) == 1 }, time.Second, 5*time.Millisecond)
	second := make(chan error, 1)
	go func() {
		_, err := m.Apply(t.Context(), []byte(`{"version":2,"epoch":100,"contained":true}`))
		second <- err
	}()
	time.Sleep(200 * time.Millisecond)
	assert.Len(t, ext.sent(), 1, "the second command waits for the first")
	require.ErrorContains(t, <-first, "did not confirm")
	require.NoError(t, <-second)
	assert.Len(t, ext.sent(), 2)
	assert.Equal(t, 2, res.lookups(), "each command resolved its own lifeline, and the confirmation adopted it")
}

// spec:agent-command-executor/the-lifeline-is-kept-current-while-contained/a-reconnected-extension-is-sent-the-lifeline-again
//
// A send reports no delivery, so after the connection to the extension is re-established the next status sends the lifeline again,
// while dials stay pinned.
func TestReconnected_TheNextStatusSendsTheLifelineAgain(t *testing.T) {
	t.Parallel()
	m, ext, res := newTestManager(t, serverTarget, nil)
	res.set("203.0.113.9")
	held := Status{Contained: true, Version: 3, Epoch: 100, Applied: true}
	m.Observe(t.Context(), held)
	m.Observe(t.Context(), held)
	require.Len(t, ext.sent(), 1)

	m.Reconnected()
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.9")}, m.pinned("edr.example.com:8443"), "dials stay pinned")
	m.Observe(t.Context(), held)
	require.Len(t, ext.sent(), 2)
	assert.Equal(t, []string{"203.0.113.9"}, ext.sent()[1].Server.Addresses)
	m.Observe(t.Context(), held)
	assert.Len(t, ext.sent(), 2)
}

// A send that completes over a connection the extension has since replaced is not recorded as sent, so the status on the new connection
// sends the lifeline again.
func TestRefresh_AReconnectDuringTheSendIsSentAgain(t *testing.T) {
	t.Parallel()
	res := &fakeResolver{}
	res.set("203.0.113.9")
	var m *Manager
	var sends atomic.Int32
	send := func([]byte) error {
		if sends.Add(1) == 1 {
			m.Reconnected()
		}
		return nil
	}
	m = New(Options{Target: serverTarget, Send: send, Resolver: res, RefreshInterval: time.Hour})
	held := Status{Contained: true, Version: 3, Epoch: 100, Applied: true}
	m.Observe(t.Context(), held)
	m.Observe(t.Context(), held)
	assert.Equal(t, int32(2), sends.Load())
	m.Observe(t.Context(), held)
	assert.Equal(t, int32(2), sends.Load(), "delivered over the current connection, it is not sent a third time")
}

// Refreshes run one at a time, so a slower lookup cannot deliver its addresses after a newer one.
func TestRefresh_OneAtATime(t *testing.T) {
	t.Parallel()
	res := &gatedResolver{started: make(chan struct{}), release: make(chan struct{})}
	m := New(Options{Target: serverTarget, Send: func([]byte) error { return nil }, Resolver: res, RefreshInterval: time.Hour})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); m.refresh(t.Context()) }()
	<-res.started
	go func() { defer wg.Done(); m.refresh(t.Context()) }()
	select {
	case <-res.started:
		t.Fatal("a second refresh looked up while the first was running")
	case <-time.After(100 * time.Millisecond):
	}
	close(res.release)
	<-res.started
	wg.Wait()
}

// An address that does not answer gets only its share of the dial deadline, so the next lifeline address is still tried in time.
func TestDialContext_AnUnansweredAddressLeavesTimeForTheNext(t *testing.T) {
	t.Parallel()
	m, _, res := newTestManager(t, serverTarget, applies)
	res.set("203.0.113.7", "203.0.113.8")
	_, err := m.Apply(t.Context(), []byte(`{"version":1,"contained":true}`))
	require.NoError(t, err)
	var mu sync.Mutex
	var reached []string
	dial := m.DialContext(func(ctx context.Context, _, addr string) (net.Conn, error) {
		if addr == "203.0.113.7:8443" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		mu.Lock()
		defer mu.Unlock()
		reached = append(reached, addr)
		return nil, nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
	defer cancel()
	_, err = dial(ctx, "tcp", "edr.example.com:8443")
	require.NoError(t, err)
	assert.Equal(t, []string{"203.0.113.8:8443"}, reached)
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

// Seed: an agent that has to enroll from scratch on a contained host dials the lifeline the extension persisted, because the status
// that would tell it arrives on a receiver loop the agent starts only after enrolling (issue #1065).
// spec:agent-command-executor/the-server-is-reached-through-the-lifeline/an-agent-starting-on-a-contained-host-reaches-the-server
func TestSeed_AdoptsTheContainmentTheExtensionPersisted(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "network-containment.json")
	doc := `{"version":7,"epoch":100,"contained":true,` +
		`"server":{"port":8443,"addresses":["203.0.113.7","2001:db8::7"],"names":["edr.example.com"]}}`
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

	m, ext, _ := newTestManager(t, serverTarget, applies)
	m.Seed(path)

	assert.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7")},
		m.pinned("edr.example.com:8443"), "the enroll dials the addresses the extension holds")
	assert.Empty(t, ext.sent(), "adopting a state sends the extension nothing: it is where the state came from")
}

func TestSeed_LeavesTheHostUncontained(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		// write says whether the file exists at all.
		write bool
	}{
		{name: "no file, the host was never contained", write: false},
		{name: "a release", body: `{"version":8,"epoch":100,"contained":false}`, write: true},
		// What decides is the contained flag: a document naming a lifeline it is not contained under is still a released host.
		{name: "a release that still names a server", write: true,
			body: `{"version":8,"epoch":100,"contained":false,"server":{"port":8443,"addresses":["203.0.113.7"]}}`},
		{name: "a containment naming no server", body: `{"version":8,"epoch":100,"contained":true}`, write: true},
		{name: "a containment naming no usable address", write: true,
			body: `{"version":8,"epoch":100,"contained":true,"server":{"port":8443,"addresses":["not-an-address"]}}`},
		{name: "not a document", body: `{`, write: true},
		// Parsing is not enough: the unspecified address matches nothing as a lifeline, and a scope the extension cannot parse would
		// have cost the document its containment there, so neither is something to pin an enroll to.
		{name: "a containment naming only the unspecified address", write: true,
			body: `{"version":8,"epoch":100,"contained":true,"server":{"port":8443,"addresses":["0.0.0.0","::"]}}`},
		// The extension refuses a document whole rather than salvaging part of it, so a file holding one it would have refused is
		// corrupt, not current. Adopting the good half would have this agent push that state back on its next lifeline refresh.
		{name: "a containment with one bad address among good ones", write: true,
			body: `{"version":8,"epoch":100,"contained":true,"server":` +
				`{"port":8443,"addresses":["203.0.113.7","nope"],"names":["edr.example.com"]}}`},
		{name: "a containment naming more addresses than the extension accepts", write: true,
			body: `{"version":8,"epoch":100,"contained":true,"server":{"port":8443,"addresses":` + manyAddresses(17) +
				`,"names":["edr.example.com"]}}`},
		{name: "a containment naming a name the extension would refuse", write: true,
			body: `{"version":8,"epoch":100,"contained":true,"server":` +
				`{"port":8443,"addresses":["203.0.113.7"],"names":["edr.example.com","-bad"]}}`},
		{name: "a containment with no version", write: true,
			body: `{"epoch":100,"contained":true,"server":{"port":8443,"addresses":["203.0.113.7"],"names":["edr.example.com"]}}`},
		{name: "a containment naming only a scoped address", write: true,
			body: `{"version":8,"epoch":100,"contained":true,"server":{"port":8443,"addresses":["fe80::1%en0"]}}`},
		// The endpoint moved while the host was contained. Pinning the old addresses under the new target would send this agent's
		// first request, the enroll secret with it, to whatever answers there.
		{name: "a containment for another port", write: true,
			body: `{"version":8,"epoch":100,"contained":true,"server":{"port":9443,"addresses":["203.0.113.7"],"names":["edr.example.com"]}}`},
		{name: "a containment for another name", write: true,
			body: `{"version":8,"epoch":100,"contained":true,"server":{"port":8443,"addresses":["203.0.113.7"],"names":["proxy.example.com"]}}`},
		{name: "a containment naming no name, for a target that is one", write: true,
			body: `{"version":8,"epoch":100,"contained":true,"server":{"port":8443,"addresses":["203.0.113.7"]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "network-containment.json")
			if tc.write {
				require.NoError(t, os.WriteFile(path, []byte(tc.body), 0o600))
			}
			m, ext, _ := newTestManager(t, serverTarget, applies)
			m.Seed(path)
			assert.Empty(t, m.pinned("edr.example.com:8443"))
			assert.Nil(t, m.state, "the host is left as it was, with no containment adopted")
			assert.Empty(t, ext.sent(), "seeding sends the extension nothing")
		})
	}
}

// An IP literal target is written as its own address and carries no name, so that is what identifies it.
// The grammar is the extension's, mirrored: a name outside it costs the document its containment there, so a file holding one is
// corrupt rather than current.
func TestIsHostName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		want bool
	}{
		{name: "edr.example.com", want: true},
		{name: "edr.example.com.", want: true},
		{name: "EDR-1.example.com", want: true},
		{name: "localhost", want: true},
		{name: "", want: false},
		{name: "-bad.example.com", want: false},
		{name: "bad-.example.com", want: false},
		{name: "edr..example.com", want: false},
		{name: "edr_1.example.com", want: false},
		{name: "edr.exämple.com", want: false},
		{name: strings.Repeat("a", 64) + ".example.com", want: false},
		{name: strings.Repeat("a", 63) + ".example.com", want: true},
		{name: strings.Repeat("a.", 127) + "b", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, isHostName(tc.name))
		})
	}
}

// manyAddresses renders a JSON array of n distinct addresses.
func manyAddresses(n int) string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("%q", fmt.Sprintf("203.0.113.%d", i+1)))
	}
	return "[" + strings.Join(out, ",") + "]"
}

func TestSeed_AnIPLiteralTargetIsIdentifiedByItsAddress(t *testing.T) {
	t.Parallel()
	literal := Target{Host: "203.0.113.7", Port: 8443}
	for _, tc := range []struct {
		name string
		body string
		// target overrides the IP literal endpoint, for a configuration that spells the same address differently.
		target  Target
		adopted bool
	}{
		{name: "the target's own address", adopted: true,
			body: `{"version":8,"epoch":100,"contained":true,"server":{"port":8443,"addresses":["203.0.113.7"]}}`},
		// The agent persists netip's canonical form, so the two sides need not be spelled alike.
		{name: "the same address written as IPv4-mapped IPv6", adopted: true, target: Target{Host: "::ffff:203.0.113.7", Port: 8443},
			body: `{"version":8,"epoch":100,"contained":true,"server":{"port":8443,"addresses":["203.0.113.7"]}}`},
		{name: "another endpoint's address", adopted: false,
			body: `{"version":8,"epoch":100,"contained":true,"server":{"port":8443,"addresses":["198.51.100.4"]}}`},
		// A document a name target left behind can name this literal among the addresses that name resolved to. Adopting the list
		// would pin addresses of an endpoint this agent is not configured for.
		{name: "the literal among another endpoint's addresses", adopted: false,
			body: `{"version":8,"epoch":100,"contained":true,"server":` +
				`{"port":8443,"addresses":["203.0.113.7","198.51.100.4"],"names":["old.example.com"]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "network-containment.json")
			require.NoError(t, os.WriteFile(path, []byte(tc.body), 0o600))
			target := literal
			if tc.target.Host != "" {
				target = tc.target
			}
			m, _, _ := newTestManager(t, target, applies)
			m.Seed(path)
			dialed := net.JoinHostPort(target.Host, "8443")
			if tc.adopted {
				assert.NotEmpty(t, m.pinned(dialed))
			} else {
				assert.Empty(t, m.pinned(dialed))
			}
		})
	}
}

// A name is one endpoint however it is written: the configuration may carry the root dot the extension's comparison drops.
func TestSeed_ANameWithTheRootDotIsTheSameEndpoint(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "network-containment.json")
	body := `{"version":8,"epoch":100,"contained":true,` +
		`"server":{"port":8443,"addresses":["203.0.113.7"],"names":["edr.example.com"]}}`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	m, _, _ := newTestManager(t, Target{Host: "EDR.example.com.", Port: 8443}, applies)
	m.Seed(path)

	assert.NotEmpty(t, m.pinned("EDR.example.com.:8443"))
}

// What the extension says now beats what a restart left on disk: a state already reported over XPC is the live answer.
func TestSeed_DoesNotReplaceAStateTheExtensionReported(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "network-containment.json")
	// Names the configured endpoint, so the document is one this agent would otherwise adopt and the state check is what refuses it.
	doc := `{"version":7,"epoch":100,"contained":true,` +
		`"server":{"port":8443,"addresses":["203.0.113.7"],"names":["edr.example.com"]}}`
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

	m, _, res := newTestManager(t, serverTarget, applies)
	res.addrs = []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	m.Observe(t.Context(), Status{Contained: true, Version: 9, Epoch: 200, Applied: true})
	m.Seed(path)

	assert.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.9")}, m.pinned("edr.example.com:8443"))
}

// spec:agent-command-executor/the-lifeline-is-kept-current-while-contained/dials-follow-the-lifeline-the-extension-confirms
//
// The defect this covers (issue #1066): an XPC send only hands the message off. If the extension refuses the refresh or its filter
// apply fails, the filter still allows the addresses it holds, so an agent that pinned dials to what it sent would dial addresses the
// filter drops, closing the lifeline the refresh exists to keep open.
func TestObserve_DialsFollowTheLifelineTheExtensionConfirms(t *testing.T) {
	t.Parallel()
	m, ext, res := newTestManager(t, serverTarget, nil)
	// The server is already at .9 while the extension holds .7, so the first status both confirms .7 and starts a refresh that sends
	// .9. That ordering is the point: the assertion below is made while a send is outstanding and unconfirmed, which is the only
	// moment the difference between pinning what was sent and what was confirmed is visible.
	res.set("203.0.113.9")
	holds := func(addrs ...string) Status {
		return Status{Contained: true, Version: 3, Epoch: 100, Applied: true, AppliedAddresses: addrs}
	}

	m.Observe(t.Context(), holds("203.0.113.7"))
	require.Len(t, ext.sent(), 1, "the new lifeline was sent")
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.7")}, m.pinned("edr.example.com:8443"),
		"dials stay on the lifeline the filter holds while the one just sent is unconfirmed")

	m.Observe(t.Context(), holds("203.0.113.9"))
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.9")}, m.pinned("edr.example.com:8443"),
		"the confirmation moves the pins")
}

// spec:agent-command-executor/the-lifeline-is-kept-current-while-contained/a-refresh-the-extension-did-not-apply-is-sent-again
//
// Before this, a refusal was permanent: the agent recorded the addresses as sent, and every later refresh resolved the same answer,
// found it equal to what was sent, and stopped. The host kept a lifeline pointing at a server that had moved.
func TestObserve_ARefreshTheExtensionDidNotApplyIsSentAgain(t *testing.T) {
	t.Parallel()
	m, ext, res := newTestManager(t, serverTarget, nil)
	// The server is at .9 and the extension keeps reporting .7: it refused each refresh, or its filter apply failed each time.
	res.set("203.0.113.9")
	holds := func(addrs ...string) Status {
		return Status{Contained: true, Version: 3, Epoch: 100, Applied: true, AppliedAddresses: addrs}
	}

	for range 3 {
		m.Observe(t.Context(), holds("203.0.113.7"))
	}
	assert.Len(t, ext.sent(), 3, "each status that does not confirm the new lifeline sends it again")
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.7")}, m.pinned("edr.example.com:8443"),
		"and dials stay on the one the filter still holds")
}

// An extension that does not report the lifeline it applied is one older than this agent. The agent keeps doing what it did before,
// because refusing to pin would send dials through the system resolver, which answers nothing while the host is contained.
func TestObserve_AnExtensionThatDoesNotReportItsLifelineStillPins(t *testing.T) {
	t.Parallel()
	m, _, res := newTestManager(t, serverTarget, nil)
	res.set("203.0.113.7")
	silent := Status{Contained: true, Version: 3, Epoch: 100, Applied: true}

	m.Observe(t.Context(), silent)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.7")}, m.pinned("edr.example.com:8443"),
		"what was sent, as before this change: there is no confirmation coming, and pinning nothing would leave the agent unable to "+
			"dial the server at all")

	// A reconnect forgets what was sent, so the next status sends the lifeline again. Against a silent extension that send is what
	// the pins follow, which is the behavior an agent had before this change and must keep against an older extension.
	res.set("203.0.113.9")
	m.Reconnected()
	m.Observe(t.Context(), silent)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.9")}, m.pinned("edr.example.com:8443"),
		"a refresh against such an extension pins what it sent")
}
