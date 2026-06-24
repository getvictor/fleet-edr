package httpserver

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// fillBuckets inserts count distinct keys with the given prefix and lastSeen so tests can craft mixed idle/live cohorts
// deterministically. Keys are prefix+"-"+i so multiple cohorts coexist without collisions.
func fillBuckets(t *testing.T, l *IPLimiter, prefix string, count int, lastSeen time.Time) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range count {
		key := prefix + "-" + strconv.Itoa(i)
		l.buckets[key] = &ipBucket{
			limiter:  rate.NewLimiter(l.limit, l.burst),
			lastSeen: lastSeen,
		}
	}
}

func TestIPLimiter_AllowAtCapacity_EvictsIdleBucketsFirst(t *testing.T) {
	t.Parallel()
	l := NewIPLimiter(rate.Limit(10), 10)

	// Fill the map: half are idle (older than IPLimiterIdleTTL), half are fresh. The idle sweep should reclaim the idle half on the next
	// Allow call so the new entry lands without touching the live cohort.
	stale := time.Now().Add(-2 * IPLimiterIdleTTL)
	fresh := time.Now()
	const halfFill = IPLimiterMaxBuckets / 2
	fillBuckets(t, l, "stale", halfFill, stale)
	fillBuckets(t, l, "fresh", IPLimiterMaxBuckets-halfFill, fresh)

	require.Len(t, l.buckets, IPLimiterMaxBuckets)

	require.True(t, l.Allow("brand-new-ip"))

	// After insert: idle half evicted, fresh half kept, plus the new
	// entry. Final size is fresh + 1.
	assert.Len(t, l.buckets, halfFill+1, "idle sweep should drop the stale half")
	_, hasNew := l.buckets["brand-new-ip"]
	assert.True(t, hasNew, "new IP must have its bucket recorded")
	_, hasStaleSurvivor := l.buckets["stale-0"]
	assert.False(t, hasStaleSurvivor, "a stale-cohort bucket must have been evicted")
}

func TestIPLimiter_AllowAtCapacity_EvictsOldestWhenAllLive(t *testing.T) {
	t.Parallel()
	l := NewIPLimiter(rate.Limit(10), 10)

	// Fill with timestamps inside IPLimiterIdleTTL but spread across a known order so the oldest is identifiable. The idle sweep won't
	// reclaim anything; the LRU fallback must drop the oldest.
	now := time.Now()
	l.mu.Lock()
	for i := range IPLimiterMaxBuckets {
		// 1ms apart so map-iteration order can't accidentally pick
		// "first encountered" instead of "oldest".
		ts := now.Add(time.Duration(i) * time.Millisecond)
		l.buckets["live-"+strconv.Itoa(i)] = &ipBucket{
			limiter:  rate.NewLimiter(l.limit, l.burst),
			lastSeen: ts,
		}
	}
	l.mu.Unlock()

	require.Len(t, l.buckets, IPLimiterMaxBuckets)

	require.True(t, l.Allow("post-cap-ip"))

	assert.Len(t, l.buckets, IPLimiterMaxBuckets, "map size cap must be honoured")
	_, oldestStillPresent := l.buckets["live-0"]
	assert.False(t, oldestStillPresent, "least-recently-seen bucket must have been evicted")
	_, postCapPresent := l.buckets["post-cap-ip"]
	assert.True(t, postCapPresent, "new IP must have its bucket recorded")
}

func TestIPLimiter_KnownIPDoesNotEvict(t *testing.T) {
	t.Parallel()
	// A repeat call from a known IP must not trigger eviction logic even if the map is at capacity: the existing bucket is hit and
	// updated in place.
	l := NewIPLimiter(rate.Limit(10), 10)
	now := time.Now()
	fillBuckets(t, l, "filler", IPLimiterMaxBuckets, now)
	require.Len(t, l.buckets, IPLimiterMaxBuckets)

	require.True(t, l.Allow("filler-0"))
	assert.Len(t, l.buckets, IPLimiterMaxBuckets, "known IP must not change map size")
}
