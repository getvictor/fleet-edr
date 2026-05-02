package httpserver

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPLimiter is a per-source-IP rate limiter shared by every public route
// in the project. Was previously duplicated inside endpoint/internal/enroll
// and identity/internal/login; centralised here so a fix to the eviction
// logic doesn't have to be made twice.
//
// Eviction policy: when the bucket map reaches IPLimiterMaxBuckets and a
// brand-new IP arrives, idle buckets (lastSeen older than IPLimiterIdleTTL)
// are swept first. If the map is still full after the sweep the
// least-recently-seen bucket is evicted. This guarantees the map size
// cannot grow past IPLimiterMaxBuckets even under a distributed spray on
// a public endpoint.
const (
	IPLimiterIdleTTL    = 2 * time.Hour
	IPLimiterMaxBuckets = 1024
)

type ipBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPLimiter is safe for concurrent use.
type IPLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	buckets map[string]*ipBucket
}

// NewIPLimiter creates a limiter with the given per-IP rate. The same
// limit + burst applies to every IP; per-IP overrides are not supported
// because every caller in the project needs the same flat shape.
func NewIPLimiter(limit rate.Limit, burst int) *IPLimiter {
	return &IPLimiter{limit: limit, burst: burst, buckets: make(map[string]*ipBucket)}
}

// Allow returns true if the given IP is within its rate budget. False
// means the request should be rejected with 429.
func (l *IPLimiter) Allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.buckets[ip]; ok {
		b.lastSeen = now
		return b.limiter.Allow()
	}
	if len(l.buckets) >= IPLimiterMaxBuckets {
		// Sweep idle buckets first (cheap, common case).
		for k, b := range l.buckets {
			if now.Sub(b.lastSeen) > IPLimiterIdleTTL {
				delete(l.buckets, k)
			}
		}
		// If still at capacity, evict the least-recently-seen bucket so
		// the map size cap is honoured even when every entry is "live".
		if len(l.buckets) >= IPLimiterMaxBuckets {
			var oldestIP string
			var oldestSeen time.Time
			for k, b := range l.buckets {
				if oldestIP == "" || b.lastSeen.Before(oldestSeen) {
					oldestIP = k
					oldestSeen = b.lastSeen
				}
			}
			delete(l.buckets, oldestIP)
		}
	}
	b := &ipBucket{limiter: rate.NewLimiter(l.limit, l.burst), lastSeen: now}
	l.buckets[ip] = b
	return b.limiter.Allow()
}

// RemoteIP returns the client IP from r.RemoteAddr, stripping the port.
// Falls back to the raw RemoteAddr if SplitHostPort fails (e.g. the
// caller used a Unix socket).
func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}
