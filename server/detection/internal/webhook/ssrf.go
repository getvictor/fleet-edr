package webhook

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
)

// ErrBlockedURL is returned when a destination URL is not https or targets a blocked address at save time.
var ErrBlockedURL = errors.New("webhook: destination URL is not allowed")

// blockedIP reports whether ip falls in a range outbound deliveries must never reach: unspecified, loopback, private (RFC1918 and
// IPv6 unique-local), link-local (which includes the cloud instance-metadata address 169.254.169.254), or multicast. The test runs on
// the parsed IP, so an IPv4-mapped IPv6 form such as ::ffff:169.254.169.254 is normalized by To4 and classified as its IPv4 form and
// cannot slip past. A nil ip (unparseable literal) is treated as blocked.
func blockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

// ValidateURL enforces the save-time destination policy: the scheme must be https, a host must be present, and a host given as an IP
// literal must not be a blocked address. A hostname that resolves is not blocked here (DNS can change); the authoritative check runs
// at delivery time in DialControl, which validates the address actually connected to and closes the DNS-rebinding gap.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: parse: %v", ErrBlockedURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: scheme must be https", ErrBlockedURL)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host", ErrBlockedURL)
	}
	if ip := net.ParseIP(host); ip != nil && blockedIP(ip) {
		return fmt.Errorf("%w: host %s is a blocked address", ErrBlockedURL, host)
	}
	return nil
}

// DialControl is a net.Dialer.Control hook that refuses to connect to a blocked address. Wiring it on the delivery client's dialer
// makes the SSRF check authoritative: it runs after DNS resolution on the concrete address about to be dialed, so a hostname that
// resolves to an internal or metadata address is rejected at connect time even if it passed the save-time literal check.
func DialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("webhook: split dial address %q: %w", address, err)
	}
	if blockedIP(net.ParseIP(host)) {
		return fmt.Errorf("webhook: refusing to connect to blocked address %s", host)
	}
	return nil
}
