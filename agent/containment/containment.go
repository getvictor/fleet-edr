// Package containment is the agent's half of host network containment (#948). It turns the server's containment state into the
// network extension's containment document, keeps the lifeline to the server resolvable and current while the host is contained, and
// dials the server through that lifeline, because the system resolver answers nothing on a contained host.
package containment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// StatusEventType is the control event type the network extension reports its containment status under. Wire contract shared with
// NetworkContainmentStatus.eventType in the extension.
const StatusEventType = "ne_containment_status"

const (
	defaultApplyTimeout    = 15 * time.Second
	defaultRefreshInterval = 5 * time.Minute
	httpsPort              = 443
	httpPort               = 80
)

// Command is the server's containment state for this host, as a set_network_containment command carries it.
type Command struct {
	Version   int64 `json:"version"`
	Epoch     int64 `json:"epoch"`
	Contained bool  `json:"contained"`
}

// Status is the network extension's report of the containment state it holds and whether its content filter applied it.
type Status struct {
	Contained bool   `json:"contained"`
	Version   int64  `json:"version"`
	Epoch     int64  `json:"epoch"`
	Applied   bool   `json:"applied"`
	Error     string `json:"error"`
}

// document is the network_containment.update the extension decodes: the command plus the lifeline.
type document struct {
	Version   int64   `json:"version"`
	Epoch     int64   `json:"epoch"`
	Contained bool    `json:"contained"`
	Server    *server `json:"server,omitempty"`
}

type server struct {
	Port      int      `json:"port"`
	Addresses []string `json:"addresses"`
	// Names is the endpoint's host name when it is one, the only name the extension's DNS proxy resolves while the host is contained.
	// Absent for an IP literal, which needs no lookup.
	Names []string `json:"names,omitempty"`
}

// Target is the endpoint the lifeline must keep reachable: the EDR server, or the proxy the agent reaches it through.
type Target struct {
	Host string
	Port int
}

// TargetFor derives the lifeline target from the server URL. When the agent's transport sends requests for that URL through a proxy
// (proxy is http.ProxyFromEnvironment in production), the proxy is what the host must keep reaching.
func TargetFor(serverURL string, proxy func(*http.Request) (*url.URL, error)) (Target, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Hostname() == "" {
		return Target{}, fmt.Errorf("server URL %q has no host", serverURL)
	}
	if proxy != nil {
		if p, perr := proxy(&http.Request{URL: u}); perr == nil && p != nil {
			u = p
		}
	}
	port := httpsPort
	if u.Scheme == "http" {
		port = httpPort
	}
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil {
			return Target{}, fmt.Errorf("server URL %q has an invalid port", serverURL)
		}
		port = n
	}
	return Target{Host: u.Hostname(), Port: port}, nil
}

// Resolver resolves the lifeline target. Production uses net.Resolver with PreferGo, which queries the configured resolvers directly:
// measured on macOS 26.3, mDNSResponder sends no query at all while the host is contained, so a getaddrinfo lookup would find nothing.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options configures a Manager.
type Options struct {
	Target Target
	// Send delivers a network_containment.update to the network extension.
	Send func(payload []byte) error
	// Resolver defaults to a Go resolver that queries the configured resolvers directly.
	Resolver Resolver
	// ApplyTimeout bounds how long Apply waits for the extension to confirm. Zero uses 15 seconds.
	ApplyTimeout time.Duration
	// RefreshInterval is how often Run re-resolves the lifeline while contained. Zero uses five minutes.
	RefreshInterval time.Duration
	Logger          *slog.Logger
}

// Manager holds the agent's view of containment and the lifeline addresses it last sent. Safe for concurrent use: commands, extension
// status events, the refresh loop and every dial of the server reach it from different goroutines.
type Manager struct {
	opts Options

	mu        sync.Mutex
	state     *Command
	addresses []netip.Addr
	// pending is the command Apply sent and is waiting on, with the addresses it sent, so the status that confirms it adopts them.
	pending          *Command
	pendingAddresses []netip.Addr
	refreshed        bool
	waiters          map[chan Status]struct{}
}

// New returns a Manager. The host starts uncontained until the extension or a command says otherwise.
func New(opts Options) *Manager {
	if opts.Resolver == nil {
		opts.Resolver = &net.Resolver{PreferGo: true}
	}
	if opts.ApplyTimeout == 0 {
		opts.ApplyTimeout = defaultApplyTimeout
	}
	if opts.RefreshInterval == 0 {
		opts.RefreshInterval = defaultRefreshInterval
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Manager{opts: opts, waiters: map[chan Status]struct{}{}}
}

// Apply runs a set_network_containment command: it resolves the lifeline for a containment, sends the extension its document, and
// waits for the extension to report that version applied. The result says what was applied; an error is the reason the command
// failed. A containment whose lifeline cannot be resolved is refused rather than sent, since it would cut the host off from the
// server that has to release it.
func (m *Manager) Apply(ctx context.Context, payload []byte) (json.RawMessage, error) {
	var cmd Command
	if err := json.Unmarshal(payload, &cmd); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}
	if cmd.Version <= 0 {
		return nil, errors.New("payload missing or invalid version")
	}
	doc := document{Version: cmd.Version, Epoch: cmd.Epoch, Contained: cmd.Contained}
	var addrs []netip.Addr
	if cmd.Contained {
		resolved, err := m.resolve(ctx)
		if err != nil {
			return nil, fmt.Errorf("resolve the lifeline to %s: %w", m.opts.Target.Host, err)
		}
		addrs = resolved
		doc.Server = m.lifelineServer(addrs)
	}
	body, _ := json.Marshal(doc)

	waiter := m.wait(&cmd, addrs)
	defer m.unwait(waiter)
	if err := m.opts.Send(body); err != nil {
		return nil, fmt.Errorf("send to the network extension: %w", err)
	}
	status, err := m.confirm(ctx, waiter, cmd)
	if err != nil {
		return nil, err
	}
	result, _ := json.Marshal(map[string]any{
		"version": cmd.Version, "contained": status.Contained, "applied": true, "lifeline": addrStrings(addrs),
	})
	return result, nil
}

// confirm waits for the extension's status for cmd. A status for a newer state means the command was superseded on the host. A status
// for this state that is not applied is pending when it carries no error, which the extension reports while the state waits behind
// an apply in flight, and a failure with the extension's reason when it does.
func (m *Manager) confirm(ctx context.Context, waiter chan Status, cmd Command) (Status, error) {
	timer := time.NewTimer(m.opts.ApplyTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return Status{}, ctx.Err()
		case <-timer.C:
			return Status{}, errors.New("the network extension did not confirm the containment state in time")
		case s := <-waiter:
			switch {
			case s.Epoch == cmd.Epoch && s.Version == cmd.Version:
				switch {
				case s.Applied:
					return s, nil
				case s.Error != "":
					return Status{}, fmt.Errorf("the network extension did not apply it: %s", s.Error)
				}
			case s.Epoch > cmd.Epoch || (s.Epoch == cmd.Epoch && s.Version > cmd.Version):
				return Status{}, fmt.Errorf("superseded on the host by version %d", s.Version)
			}
		}
	}
}

// Observe records a status the extension reported. The extension reports its state on every agent connect, so this is how an agent
// that restarts while the host is contained learns it: the first contained status it sees triggers a lifeline refresh, sent at that
// state's version, which the extension accepts only if the addresses moved.
func (m *Manager) Observe(ctx context.Context, s Status) {
	m.mu.Lock()
	for w := range m.waiters {
		select {
		case w <- s:
		default:
		}
	}
	adopt := s.Applied && (m.state == nil || s.Epoch != m.state.Epoch || s.Version != m.state.Version || s.Contained != m.state.Contained)
	if adopt {
		m.state = &Command{Version: s.Version, Epoch: s.Epoch, Contained: s.Contained}
		m.refreshed = false
		m.addresses = nil
		if m.pending != nil && m.pending.Epoch == s.Epoch && m.pending.Version == s.Version {
			// The command this agent just sent: the extension holds exactly the addresses sent with it. Any other state, such as a
			// containment held across an agent restart, leaves the addresses unknown, and the refresh below sends what the target
			// resolves to now.
			m.addresses = m.pendingAddresses
			m.refreshed = true
		}
	}
	refresh := s.Contained && s.Applied && !m.refreshed
	m.mu.Unlock()
	if refresh {
		m.refresh(ctx)
	}
}

// Run re-resolves the lifeline every RefreshInterval while the host is contained, and sends the extension the new addresses when they
// moved, so a server whose addresses change does not lose a contained host.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.opts.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			contained := m.state != nil && m.state.Contained
			m.refreshed = false
			m.mu.Unlock()
			if contained {
				m.refresh(ctx)
			}
		}
	}
}

// refresh resolves the lifeline and sends it at the current state's version when the addresses differ from the ones last sent.
func (m *Manager) refresh(ctx context.Context) {
	addrs, err := m.resolve(ctx)
	if err != nil {
		m.opts.Logger.WarnContext(ctx, "network containment lifeline refresh: resolve failed; keeping the addresses in force", "err", err)
		return
	}
	m.mu.Lock()
	if m.state == nil || !m.state.Contained {
		m.mu.Unlock()
		return
	}
	m.refreshed = true
	if slices.Equal(addrs, m.addresses) {
		m.mu.Unlock()
		return
	}
	doc := document{Version: m.state.Version, Epoch: m.state.Epoch, Contained: true, Server: m.lifelineServer(addrs)}
	m.addresses = addrs
	m.mu.Unlock()
	body, _ := json.Marshal(doc)
	if err := m.opts.Send(body); err != nil {
		m.opts.Logger.WarnContext(ctx, "network containment lifeline refresh: send failed", "err", err)
		m.mu.Lock()
		m.refreshed = false
		m.mu.Unlock()
		return
	}
	m.opts.Logger.InfoContext(ctx, "network containment lifeline refreshed", "addresses", doc.Server.Addresses)
}

// DialContext wraps a dialer so connections to the lifeline target go to the lifeline addresses while the host is contained. The
// system resolver answers nothing then, so a dial by name would fail even though the lifeline is open. Every other dial, and every
// dial while the host is not contained, goes to base unchanged.
func (m *Manager) DialContext(base func(ctx context.Context, network, addr string) (net.Conn, error)) func(
	ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		addrs := m.pinned(addr)
		if len(addrs) == 0 {
			return base(ctx, network, addr)
		}
		var errs []error
		for _, a := range addrs {
			conn, err := base(ctx, network, netip.AddrPortFrom(a, uint16(m.opts.Target.Port)).String()) //nolint:gosec // a validated TCP port
			if err == nil {
				return conn, nil
			}
			errs = append(errs, err)
		}
		return nil, errors.Join(errs...)
	}
}

// pinned returns the lifeline addresses when addr is the lifeline target. They are empty whenever the host is not contained: a release,
// and every state other than a containment, clears them.
func (m *Manager) pinned(addr string) []netip.Addr {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || !strings.EqualFold(host, m.opts.Target.Host) || port != strconv.Itoa(m.opts.Target.Port) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.addresses)
}

// lifelineServer is the document's server: the target's port, the addresses it resolved to, and its name when it is not an IP literal.
func (m *Manager) lifelineServer(addrs []netip.Addr) *server {
	s := &server{Port: m.opts.Target.Port, Addresses: addrStrings(addrs)}
	if _, err := netip.ParseAddr(m.opts.Target.Host); err != nil {
		s.Names = []string{m.opts.Target.Host}
	}
	return s
}

func (m *Manager) resolve(ctx context.Context) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(m.opts.Target.Host); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	addrs, err := m.opts.Resolver.LookupNetIP(ctx, "ip", m.opts.Target.Host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a = a.Unmap(); a.IsValid() && !a.IsUnspecified() && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no usable addresses")
	}
	const maxLifelineAddresses = 16 // the extension refuses more
	if len(out) > maxLifelineAddresses {
		out = out[:maxLifelineAddresses]
	}
	return out, nil
}

func (m *Manager) wait(cmd *Command, addrs []netip.Addr) chan Status {
	w := make(chan Status, 4)
	m.mu.Lock()
	m.waiters[w] = struct{}{}
	m.pending, m.pendingAddresses = cmd, addrs
	m.mu.Unlock()
	return w
}

func (m *Manager) unwait(w chan Status) {
	m.mu.Lock()
	delete(m.waiters, w)
	m.pending, m.pendingAddresses = nil, nil
	m.mu.Unlock()
}

// ParseStatus recognises a containment status control message. The second result is false for every other event, checked with a
// type peek first because this runs on every network-extension event.
func ParseStatus(data []byte) (Status, bool) {
	var hdr struct {
		EventType string `json:"event_type"`
	}
	if err := json.Unmarshal(data, &hdr); err != nil || hdr.EventType != StatusEventType {
		return Status{}, false
	}
	var envelope struct {
		Payload Status `json:"payload"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Status{Error: "undecodable containment status"}, true
	}
	return envelope.Payload, true
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}
