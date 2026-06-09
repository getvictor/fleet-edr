package breakglass

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/fleetdm/edr/server/httpserver"
)

// Allowlist is the optional IP gate that wraps the break-glass
// surface. Off-allowlist requests receive a generic 404 - the spec
// is explicit that the path's existence MUST NOT be acknowledged to
// off-list callers, so an attacker probing for `/admin/break-glass`
// from outside the operator's bastion-host subnet sees the same
// response as an entirely unmapped URL.
//
// Empty allowlist (zero CIDRs) passes through every request. Empty
// is the wave-1 default for dev workflows where nobody has set the
// EDR_BREAKGLASS_IP_ALLOWLIST env var yet.
type Allowlist struct {
	cidrs []*net.IPNet
}

// NewAllowlist parses each CIDR / single-IP entry and returns a
// configured allowlist. A bare IP (no CIDR) is normalised to a /32
// (IPv4) or /128 (IPv6) so operators can type "203.0.113.5" without
// remembering CIDR syntax.
//
// Returns an error on the first malformed entry so a typo at boot
// surfaces as "refuse to start" rather than silently leaving the
// surface open.
func NewAllowlist(entries []string) (*Allowlist, error) {
	out := &Allowlist{}
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("breakglass allowlist: %q is not a valid IP or CIDR", entry)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			entry = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("breakglass allowlist: %q: %w", entry, err)
		}
		out.cidrs = append(out.cidrs, cidr)
	}
	return out, nil
}

// Allows reports whether ip is on the allowlist. An empty allowlist (zero CIDRs) returns true: dev mode without an explicit list is
// unrestricted.
func (a *Allowlist) Allows(ip net.IP) bool {
	if a == nil || len(a.cidrs) == 0 {
		return true
	}
	for _, cidr := range a.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// Middleware wraps next so off-allowlist callers receive a generic 404 indistinguishable from a non-existent route. On-list callers
// pass through. The IP is resolved via httpserver.ClientIP, which honours the X-Forwarded-For trust list configured at boot.
func (a *Allowlist) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a == nil || len(a.cidrs) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		ipStr := httpserver.ClientIP(r)
		ip := net.ParseIP(ipStr)
		if ip == nil || !a.Allows(ip) {
			// Generic 404 with the same body shape Go's stdlib serves for an unrouted path. We deliberately do NOT log at
			// WARN here because attackers triggering this path generates noise; the per-IP rate limiter sitting in front
			// catches the volumetric signal.
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
