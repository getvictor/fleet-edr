// Package ratewindow implements a fixed-window counter used to cap how often a single host may push
// oversized event batches before the ingest path starts shedding them.
package ratewindow

import (
	"sync"
	"time"
)

// Counter tracks hits per host inside a fixed time window. A host that exceeds limit within one
// window is throttled until the window rolls over.
type Counter struct {
	mu       sync.Mutex
	window   time.Duration
	limit    int
	hits     map[string]int
	windowAt time.Time
}

// New builds a Counter over the supplied window with the supplied per-host limit.
func New(window time.Duration, limit int) *Counter {
	return &Counter{
		window:   window,
		limit:    limit,
		hits:     make(map[string]int),
		windowAt: time.Now(),
	}
}

// Allow records a hit for hostID and reports whether the caller is still under the limit.
func (c *Counter) Allow(hostID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.windowAt) > c.window {
		c.hits = make(map[string]int)
		c.windowAt = time.Now()
	}

	c.hits[hostID]++
	return c.hits[hostID] <= c.limit
}

// Remaining reports how many hits hostID has left in the current window.
func (c *Counter) Remaining(hostID string) int {
	return c.limit - c.hits[hostID]
}

// Reset clears every counter and starts a fresh window.
func (c *Counter) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hits = make(map[string]int)
	c.windowAt = time.Now()
}
