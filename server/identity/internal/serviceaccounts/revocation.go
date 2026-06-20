package serviceaccounts

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultRevocationRefreshInterval is how often each replica reloads the revocation snapshot from the database. It bounds the
// revocation staleness window (how long a just-revoked service account's outstanding access token keeps validating on a replica)
// against hammering the DB. Mirrors the host-token snapshot cadence (#454).
const DefaultRevocationRefreshInterval = 5 * time.Second

// Entry is one service account's revocation state. Revoked is terminal; Epoch is the account's current epoch, against which a
// presented token's epoch is compared.
type Entry struct {
	ClientID string
	Epoch    int64
	Revoked  bool
}

// Source loads the current set of revoked-or-bumped service accounts. The Store implements it.
type Source interface {
	RevocationEntries(ctx context.Context) ([]Entry, error)
}

// Snapshot is a refreshable, concurrent-read view of service-account revocation state. Per ADR-0010 it is a per-replica performance
// cache that is safe to lose: it rebuilds from MySQL on every refresh.
type Snapshot struct {
	src    Source
	logger *slog.Logger

	mu sync.RWMutex
	// entries is a per-replica perf cache, safe to lose: it is rebuilt from MySQL on every Refresh and holds only revoked/rotated
	// accounts, so a lost snapshot fails open until the next refresh rather than corrupting state.
	entries map[string]Entry

	lastRefreshUnix atomic.Int64
}

// NewSnapshot constructs a snapshot over src. It starts empty (allows everything) until the first Refresh; callers should Refresh once
// synchronously before serving so a cold replica does not accept an already-revoked token.
func NewSnapshot(src Source, logger *slog.Logger) *Snapshot {
	if src == nil {
		panic("serviceaccounts.NewSnapshot: Source must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Snapshot{src: src, logger: logger, entries: map[string]Entry{}}
}

// Allowed reports whether a token presenting tokenEpoch for clientID is currently allowed. An account absent from the snapshot is
// allowed (never revoked, never rotated). A revoked account is never allowed. Otherwise the token must carry an epoch at least the
// account's current epoch.
func (s *Snapshot) Allowed(clientID string, tokenEpoch int64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[clientID]
	if !ok {
		return true
	}
	if e.Revoked {
		return false
	}
	return tokenEpoch >= e.Epoch
}

// Size returns the number of accounts currently in the snapshot.
func (s *Snapshot) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Refresh reloads the snapshot from the source. On error the previous snapshot is retained (stale beats empty: dropping to empty
// would briefly un-revoke every cut-off account) and the failure is logged.
func (s *Snapshot) Refresh(ctx context.Context) error {
	rows, err := s.src.RevocationEntries(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "service-account revocation snapshot refresh failed; serving previous snapshot", "err", err)
		return err
	}
	next := make(map[string]Entry, len(rows))
	for _, r := range rows {
		next[r.ClientID] = r
	}
	s.mu.Lock()
	s.entries = next
	s.mu.Unlock()
	s.lastRefreshUnix.Store(time.Now().Unix())
	return nil
}

// Run refreshes once immediately, then on every interval tick until ctx is cancelled.
func (s *Snapshot) Run(ctx context.Context, interval time.Duration) {
	_ = s.Refresh(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.Refresh(ctx)
		}
	}
}
