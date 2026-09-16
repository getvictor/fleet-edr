// Package containment is the agent's half of host network containment (#948). It turns the server's containment state into the
// network extension's containment document, keeps the lifeline to the server resolvable and current while the host is contained, and
// dials the server through that lifeline, because the system resolver answers nothing on a contained host.
package containment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
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
	socksPort              = 1080
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
	// The default ports net/http dials for each scheme a proxy URL can carry.
	port := httpsPort
	switch u.Scheme {
	case "http":
		port = httpPort
	case "socks5", "socks5h":
		port = socksPort
	}
	if p := u.Port(); p != "" {
		// The extension refuses a lifeline port outside 1 to 65535, so a URL naming one yields no target rather than a refused containment.
		n, perr := strconv.ParseUint(p, 10, 16)
		if perr != nil || n == 0 {
			return Target{}, fmt.Errorf("server URL %q has an invalid port", serverURL)
		}
		port = int(n)
	}
	return Target{Host: u.Hostname(), Port: port}, nil
}

// ExtensionStatePath is where the network extension persists the containment it holds. The agent reads it once at startup, before it
// can be told the state over XPC, so a contained host's first connection to the server already goes to the lifeline addresses.
const ExtensionStatePath = "/var/db/com.fleetdm.edr/network-containment.json"

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

	// applyMu runs one command at a time: the poll and push transports can each execute a containment command at once.
	applyMu sync.Mutex
	// refreshMu runs one lifeline refresh at a time, so a slower lookup cannot deliver its addresses after a newer one.
	refreshMu sync.Mutex

	mu    sync.Mutex
	state *Command
	// addresses are the lifeline addresses dials of the target are pinned to. sent are the ones sent over the current connection to
	// the extension, which a reconnect forgets: a send reports no delivery, so addresses sent over a dropped connection may never
	// have arrived.
	addresses []netip.Addr
	sent      []netip.Addr
	// generation counts reconnects to the extension, so a send that completes over a connection that has since been replaced is not
	// recorded as sent.
	generation uint64
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

// Seed adopts the containment the network extension persisted, pinning the lifeline addresses it holds.
//
// Why this exists (issue #1065). The manager otherwise learns containment only from the extension's status, which arrives on the
// receiver loop the agent starts after enrolling. An agent with a saved token does not care, because loading it makes no network call,
// but one that has to enroll from scratch, after a reinstall cleared its token while the host was contained, dials the server by name
// before any status has arrived. On a contained host the system resolver answers nothing, the enroll fails, launchd restarts the agent,
// and the host can no longer be released from the console. Reading the state the extension already persisted closes that.
//
// The extension's own word still wins: a state reported over XPC replaces this, and nothing is sent to the extension here. A file that
// is missing, unreadable, not a containment, or names no usable address leaves the host uncontained, which is what it was before.
func (m *Manager) Seed(path string) {
	// #nosec G304 -- the path is this package's own constant in production and a test's temporary file otherwise; it is never
	// attacker-supplied, and the file is written by the network extension as root.
	data, err := os.ReadFile(path)
	if err != nil {
		// Missing is the ordinary case: a host that has never been contained has no file.
		if !errors.Is(err, fs.ErrNotExist) {
			m.opts.Logger.WarnContext(context.Background(), "network containment: the extension's persisted state could not be read",
				"path", path, "err", err)
		}
		return
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		m.opts.Logger.WarnContext(context.Background(), "network containment: the extension's persisted state could not be decoded",
			"path", path, "err", err)
		return
	}
	if !doc.Contained || doc.Server == nil {
		return
	}
	if !m.describesTarget(doc.Server) {
		// The endpoint moved while the host was contained: a changed EDR_SERVER_URL, or a proxy added or removed. Pinning the old
		// endpoint's addresses under the new target would send this agent's first request, the enroll secret with it, to whatever
		// answers at the previous address. The enrollment path refuses a token bound to another server for the same reason.
		m.opts.Logger.WarnContext(context.Background(),
			"network containment: the extension's persisted state names another endpoint, so it was not adopted",
			"target", net.JoinHostPort(m.opts.Target.Host, strconv.Itoa(m.opts.Target.Port)),
			"persisted_port", doc.Server.Port, "persisted_names", doc.Server.Names)
		return
	}
	addrs, ok := adoptableAddresses(doc)
	if !ok {
		m.opts.Logger.WarnContext(context.Background(),
			"network containment: the extension's persisted state is not one it would hold, so it was not adopted", "path", path,
			"version", doc.Version, "addresses", doc.Server.Addresses, "port", doc.Server.Port)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != nil {
		// The extension has already said what it holds, which is the live answer rather than what a restart left on disk.
		return
	}
	m.state = &Command{Version: doc.Version, Epoch: doc.Epoch, Contained: true}
	m.addresses = addrs
	// sent stays empty: these addresses were sent by whichever agent run wrote them, over a connection this one does not hold, so the
	// first status starts a refresh that sends what the target resolves to now.
	m.opts.Logger.InfoContext(context.Background(), "network containment: adopted the state the extension persisted",
		"version", doc.Version, "epoch", doc.Epoch, "addresses", doc.Server.Addresses)
}

// adoptableAddresses is the lifeline of a persisted document, and whether the document is one the extension would hold at all.
//
// The extension refuses a containment document WHOLE: a bad address among good ones, more addresses than it accepts, a port outside
// the range, and it cannot decode one without a version. So a document failing any of those was never applied there, and a file
// holding one is corrupt rather than current. Salvaging what parses would leave this agent believing in a containment the extension
// does not hold, and its lifeline refresh would then push that state back to the extension, containing a host on the strength of a
// damaged file. The name grammar is left to the extension, which polices what it will hold: the agent only compares a name against
// the endpoint it is configured for, which a malformed one cannot match.
func adoptableAddresses(doc document) ([]netip.Addr, bool) {
	if doc.Version <= 0 || doc.Server.Port < 1 || doc.Server.Port > maxPort {
		return nil, false
	}
	if len(doc.Server.Addresses) == 0 || len(doc.Server.Addresses) > maxLifelineAddresses ||
		len(doc.Server.Names) > maxLifelineNames {
		return nil, false
	}
	addrs := make([]netip.Addr, 0, len(doc.Server.Addresses))
	for _, a := range doc.Server.Addresses {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return nil, false
		}
		if addr = addr.Unmap(); !addr.IsValid() || addr.IsUnspecified() || addr.Zone() != "" {
			return nil, false
		}
		addrs = append(addrs, addr)
	}
	return addrs, true
}

// describesTarget reports whether a persisted lifeline is the one this agent's configured endpoint would have. The port must match,
// and the endpoint must be named: by host name when the target is a name, and among the addresses when it is an IP literal, which is
// how the agent writes each case.
func (m *Manager) describesTarget(s *server) bool {
	if s.Port != m.opts.Target.Port {
		return false
	}
	// By value on both sides, because neither is written only one way: an address is persisted as netip's canonical form, so a
	// configuration naming the same address as an IPv4-mapped or non-canonical IPv6 literal would not compare equal as text, and a
	// name may carry the root dot that the extension's own comparison drops.
	if target, err := netip.ParseAddr(m.opts.Target.Host); err == nil {
		target = target.Unmap()
		return slices.ContainsFunc(s.Addresses, func(a string) bool {
			addr, perr := netip.ParseAddr(a)
			return perr == nil && addr.Unmap() == target
		})
	}
	host := normalizedName(m.opts.Target.Host)
	return slices.ContainsFunc(s.Names, func(n string) bool { return normalizedName(n) == host })
}

// normalizedName is a host name as a comparison should see it: case folded, without the trailing root dot.
func normalizedName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Apply runs a set_network_containment command: it resolves the lifeline for a containment, sends the extension its document, and
// waits for the extension to report that version applied. The result says what was applied; an error is the reason the command
// failed. A containment whose lifeline cannot be resolved is refused rather than sent, since it would cut the host off from the
// server that has to release it.
func (m *Manager) Apply(ctx context.Context, payload []byte) (json.RawMessage, error) {
	var fields struct {
		Version   int64 `json:"version"`
		Epoch     int64 `json:"epoch"`
		Contained *bool `json:"contained"`
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}
	if fields.Version <= 0 {
		return nil, errors.New("payload missing or invalid version")
	}
	// Required rather than defaulted: a payload that lost the field must not turn into a release.
	if fields.Contained == nil {
		return nil, errors.New("payload missing contained")
	}
	cmd := Command{Version: fields.Version, Epoch: fields.Epoch, Contained: *fields.Contained}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
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
				case s.Contained != cmd.Contained:
					// The extension refused this state because it holds a different one at the same version.
					return Status{}, fmt.Errorf("the host holds a different state at version %d", s.Version)
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
		m.addresses, m.sent = nil, nil
		if m.pending != nil && *m.pending == *m.state {
			// The command this agent just sent: the extension holds exactly the addresses sent with it. Any other state, such as a
			// containment held across an agent restart, leaves the addresses unknown, and the refresh below sends what the target
			// resolves to now.
			m.addresses, m.sent = m.pendingAddresses, m.pendingAddresses
			m.refreshed = true
		}
	}
	refresh := s.Contained && s.Applied && !m.refreshed
	m.mu.Unlock()
	if refresh {
		m.refresh(ctx)
	}
}

// Reconnected notes that the connection to the network extension was re-established. The lifeline is sent again on the next status,
// because a send reports no delivery and one made over the dropped connection may never have arrived. Dials stay pinned meanwhile.
func (m *Manager) Reconnected() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generation++
	m.sent = nil
	m.refreshed = false
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
			m.mu.Unlock()
			if contained {
				m.refresh(ctx)
			}
		}
	}
}

// refresh resolves the lifeline and sends it at the current state's version when the addresses differ from the ones last sent.
func (m *Manager) refresh(ctx context.Context) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	addrs, err := m.resolve(ctx)
	if err != nil {
		m.opts.Logger.WarnContext(ctx, "network containment lifeline refresh: resolve failed; keeping the addresses in force", "err", err)
		return
	}
	m.mu.Lock()
	// The state can change while the lookup runs: a release adopted meanwhile must not be answered with a containment document.
	if m.state == nil || !m.state.Contained {
		m.mu.Unlock()
		return
	}
	m.refreshed = true
	if slices.Equal(addrs, m.sent) {
		m.mu.Unlock()
		return
	}
	state, generation := *m.state, m.generation
	m.mu.Unlock()
	doc := document{Version: state.Version, Epoch: state.Epoch, Contained: true, Server: m.lifelineServer(addrs)}
	body, _ := json.Marshal(doc)
	if err := m.opts.Send(body); err != nil {
		// Nothing is recorded as sent, so the next status or refresh tries again rather than finding these addresses already sent.
		m.opts.Logger.WarnContext(ctx, "network containment lifeline refresh: send failed", "err", err)
		m.mu.Lock()
		m.refreshed = false
		m.mu.Unlock()
		return
	}
	m.mu.Lock()
	if m.state != nil && *m.state == state && m.generation == generation {
		m.addresses, m.sent = addrs, addrs
	}
	m.mu.Unlock()
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
		for i, a := range addrs {
			conn, err := dialShare(ctx, len(addrs)-i, func(ctx context.Context) (net.Conn, error) {
				return base(ctx, network, netip.AddrPortFrom(a, uint16(m.opts.Target.Port)).String()) //nolint:gosec // a validated TCP port
			})
			if err == nil {
				return conn, nil
			}
			errs = append(errs, err)
		}
		return nil, errors.Join(errs...)
	}
}

// dialShare runs one dial attempt with an equal share of the time left before ctx's deadline across the remaining attempts, so an
// address that does not answer cannot use up the time the next one needs. Without a deadline the attempt runs under ctx.
func dialShare(ctx context.Context, remaining int, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return dial(ctx)
	}
	attempt, cancel := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(remaining))
	defer cancel()
	return dial(attempt)
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

// resolve returns the target's lifeline addresses: the target itself when it is an IP literal, otherwise what it resolves to. Either way
// they are unmapped, deduplicated and capped, and an address the extension would refuse (unspecified, or with a zone) is dropped.
func (m *Manager) resolve(ctx context.Context) ([]netip.Addr, error) {
	addrs := []netip.Addr{}
	if literal, err := netip.ParseAddr(m.opts.Target.Host); err == nil {
		addrs = append(addrs, literal)
	} else if addrs, err = m.opts.Resolver.LookupNetIP(ctx, "ip", m.opts.Target.Host); err != nil {
		return nil, err
	}
	out := usableAddresses(addrs)
	if len(out) == 0 {
		return nil, errors.New("no usable addresses")
	}
	return out, nil
}

// What the extension accepts in a containment document, mirrored here so the agent adopts only what it would hold.
const (
	maxLifelineAddresses = 16
	maxLifelineNames     = 4
	maxPort              = 65535
)

// usableAddresses is what may become a lifeline: a valid address that is not the unspecified one, unmapped, unscoped and not already
// present, up to the number the extension accepts. The unspecified address as a lifeline matches nothing, and a scope the extension
// cannot parse costs the containment its whole document.
func usableAddresses(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a = a.Unmap(); a.IsValid() && !a.IsUnspecified() && a.Zone() == "" && !slices.Contains(out, a) {
			out = append(out, a)
		}
		if len(out) == maxLifelineAddresses {
			break
		}
	}
	return out
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

// DecodeStatus decodes a control event already identified by its event_type as a StatusEventType. The receiver peeks at the type once
// for every network-extension event, so this runs only on the rare status. A status that does not decode, or names no state, comes
// back not applied and marked undecodable, so it adopts nothing.
func DecodeStatus(data []byte) Status {
	var envelope struct {
		Payload Status `json:"payload"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil || envelope.Payload.Version <= 0 {
		return Status{Error: "undecodable containment status"}
	}
	return envelope.Payload
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}
