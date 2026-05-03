package httpserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIPResolver resolves the trustworthy client IP from an
// *http.Request when fleet-edr-server is deployed behind one or more
// reverse proxies / load balancers.
//
// Issue #81. Default behaviour (zero or empty trusted list) is the
// pre-existing "ignore X-Forwarded-For, return the direct peer IP"
// stance: trusting XFF from any caller lets a client spoof its logged
// source IP and collapses the per-IP rate limiter into a single
// shared bucket. The resolver only honours XFF when the immediate TCP
// peer (r.RemoteAddr) is itself a configured trusted proxy.
//
// Resolution rules:
//
//   - r.RemoteAddr is NOT in any trusted CIDR -> return its host
//     portion. XFF is ignored regardless of contents.
//   - r.RemoteAddr IS in a trusted CIDR -> walk the X-Forwarded-For
//     chain right-to-left, skip entries that themselves match a
//     trusted CIDR, and return the first non-trusted entry. If every
//     entry is trusted (or the chain is empty / malformed) fall back
//     to the peer IP.
//
// The right-to-left walk handles chained proxies (alb -> nginx ->
// fleet-edr-server) safely: each hop appends to XFF, so the rightmost
// non-trusted entry is the closest hop the trusted infrastructure
// vouches for. The leftmost entry is whatever the client originally
// claimed and is never inherently trustworthy.
type ClientIPResolver struct {
	trusted []netip.Prefix
}

// NewClientIPResolver parses cidrs into trusted prefixes. Each entry
// may be either a CIDR ("10.0.0.0/8") or a bare IP ("192.168.1.5"),
// in which case it is treated as /32 (IPv4) or /128 (IPv6). nil or
// empty input yields a resolver that returns the direct peer IP for
// every call (the secure default).
//
// Returns an error naming the offending entry on the first bad token
// so an operator can fix the env var without playing whack-a-mole.
func NewClientIPResolver(cidrs []string) (*ClientIPResolver, error) {
	r := &ClientIPResolver{}
	for _, raw := range cidrs {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		prefix, err := parseTrustedPrefix(token)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", raw, err)
		}
		r.trusted = append(r.trusted, prefix)
	}
	return r, nil
}

func parseTrustedPrefix(token string) (netip.Prefix, error) {
	if strings.Contains(token, "/") {
		p, err := netip.ParsePrefix(token)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(token)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits), nil
}

// ClientIP resolves the trustworthy client IP for r per the rules in
// the type doc. Returns "" when r is nil. A nil receiver is treated
// as an empty trusted list — useful for tests and for the boot path
// before the resolver is constructed.
func (c *ClientIPResolver) ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	peer := remoteHost(r.RemoteAddr)
	if c == nil || len(c.trusted) == 0 {
		return peer
	}
	peerAddr, ok := parseAddr(peer)
	if !ok || !c.isTrusted(peerAddr) {
		return peer
	}
	// Peer is trusted: walk the XFF chain right-to-left, skipping
	// trusted hops. r.Header.Values returns one entry per header (some
	// proxies emit multiple); each entry may itself contain a
	// comma-separated chain.
	values := r.Header.Values("X-Forwarded-For")
	for i := len(values) - 1; i >= 0; i-- {
		parts := strings.Split(values[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			entry := strings.TrimSpace(parts[j])
			if entry == "" {
				continue
			}
			addr, ok := parseAddr(entry)
			if !ok {
				continue
			}
			if c.isTrusted(addr) {
				continue
			}
			return addr.String()
		}
	}
	// Every XFF entry was trusted (or the chain was empty / malformed).
	// The peer is the most reliable thing left.
	return peer
}

func (c *ClientIPResolver) isTrusted(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range c.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// remoteHost strips the port from a "host:port" string. Falls back to
// the trimmed input when SplitHostPort fails (e.g. Unix socket peer
// or a test that passed an already-stripped IP).
func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return strings.TrimSpace(remoteAddr)
	}
	return host
}

func parseAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// Middleware returns an http.Handler middleware that resolves the
// client IP once per request and stashes it on ctx so downstream
// handlers (rate limiter, audit recorders, access log) read the same
// value. Idempotent if installed more than once on a request.
func (c *ClientIPResolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := c.ClientIP(r)
		ctx := context.WithValue(r.Context(), clientIPCtxKey{}, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type clientIPCtxKey struct{}

// ClientIP returns the resolved client IP for r. When the resolver
// middleware ran on r the value comes from ctx; otherwise the direct
// peer IP (port stripped) is returned. Safe to call before any
// resolver is wired (returns peer IP).
//
// Production code should always call this rather than
// httpserver.RemoteIP or r.RemoteAddr directly: the test harness sets
// it via middleware, prod sets it via middleware, and the fallback
// keeps tests that don't go through the middleware chain working.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := r.Context().Value(clientIPCtxKey{}); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return RemoteIP(r)
}
