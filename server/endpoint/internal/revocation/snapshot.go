// Package revocation maintains a per-replica in-memory view of which host enrollments are revoked or have had their token epoch
// bumped, so the agent auth hot path can reject revoked tokens without a per-request database lookup.
//
// Self-validating signed tokens (see internal/signedtoken) prove a token is authentic and unexpired with a local HMAC check and no DB
// access. The one thing a signature cannot prove is "still allowed": an operator may have revoked the host or cycled its credentials
// since the token was minted. This snapshot supplies that answer. It loads the small set of hosts that are revoked or epoch-bumped
// (the overwhelming majority of a fleet is neither, so the map stays tiny even at 100k hosts) and refreshes on a ticker. A host absent
// from the snapshot is allowed; a present host is rejected outright if revoked, or if the presented token's epoch is below the host's
// current epoch.
//
// Per ADR-0010 this is a per-replica perf cache, safe to lose: a fresh replica rebuilds it from the database on startup and on every
// refresh tick, and holds no state a peer replica needs. Revocation is therefore eventually consistent across replicas, bounded by the
// refresh interval. That is the deliberate trade for removing the per-request DB lookup.
package revocation

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "github.com/fleetdm/edr/server/endpoint/revocation"

// Entry is one host's revocation state. Revoked is terminal (the host is cut off regardless of epoch); Epoch is the host's current
// token_epoch, against which a presented token's epoch is compared.
type Entry struct {
	HostID  string
	Epoch   int64
	Revoked bool
}

// Source loads the current set of revoked-or-bumped hosts. The mysql store implements it. Only hosts that are revoked or have a
// non-zero token_epoch are returned, so the result set is bounded by the count of cut-off / cycled hosts, not the fleet size.
type Source interface {
	RevocationEntries(ctx context.Context) ([]Entry, error)
}

// Snapshot is a refreshable, concurrent-read view of revocation state.
type Snapshot struct {
	src    Source
	logger *slog.Logger

	mu      sync.RWMutex
	entries map[string]Entry

	refreshFailures metric.Int64Counter
	lastRefreshUnix atomic.Int64
}

// NewSnapshot constructs a snapshot over src. It starts empty (allows everything) until the first Refresh; callers should Refresh once
// synchronously before serving so a cold replica does not accept an already-revoked token. Registers OTel instruments for size, age,
// and refresh failures so an operator can see the snapshot is live in SigNoz.
func NewSnapshot(src Source, logger *slog.Logger) *Snapshot {
	if src == nil {
		panic("revocation.NewSnapshot: Source must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Snapshot{
		src:     src,
		logger:  logger,
		entries: map[string]Entry{},
	}
	meter := otel.Meter(meterName)
	s.refreshFailures, _ = meter.Int64Counter(
		"edr.auth.revocation_snapshot.refresh_failures",
		metric.WithDescription("Revocation snapshot refresh attempts that failed; a sustained non-zero rate means revocations are going stale on this replica."),
		metric.WithUnit("{failure}"),
	)
	_, _ = meter.Int64ObservableGauge(
		"edr.auth.revocation_snapshot.size",
		metric.WithDescription("Number of hosts currently revoked or epoch-bumped in this replica's revocation snapshot."),
		metric.WithUnit("{host}"),
		metric.WithInt64Callback(func(_ context.Context, obs metric.Int64Observer) error {
			obs.Observe(int64(s.Size()))
			return nil
		}),
	)
	_, _ = meter.Float64ObservableGauge(
		"edr.auth.revocation_snapshot.age_seconds",
		metric.WithDescription("Seconds since the revocation snapshot last refreshed successfully on this replica."),
		metric.WithUnit("s"),
		metric.WithFloat64Callback(func(_ context.Context, obs metric.Float64Observer) error {
			last := s.lastRefreshUnix.Load()
			if last == 0 {
				return nil
			}
			obs.Observe(time.Since(time.Unix(last, 0)).Seconds())
			return nil
		}),
	)
	return s
}

// Allowed reports whether a token presenting tokenEpoch for hostID is currently allowed. A host absent from the snapshot is allowed
// (not revoked, never cycled). A revoked host is never allowed. Otherwise the token must carry an epoch at least the host's current
// epoch.
func (s *Snapshot) Allowed(hostID string, tokenEpoch int64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[hostID]
	if !ok {
		return true
	}
	if e.Revoked {
		return false
	}
	return tokenEpoch >= e.Epoch
}

// Size returns the number of hosts currently in the snapshot (revoked or epoch-bumped).
func (s *Snapshot) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Observe records a host's post-enrollment revocation state on this replica so a freshly issued token is accepted immediately, without
// waiting for the next refresh. The service calls this on a successful (re-)enrollment with the epoch the row now carries: the host has
// proven the enroll secret and its row was reset to a not-revoked state, but its token_epoch is PRESERVED across a re-enroll so an
// operator credential cycle survives. Setting the entry to {epoch, not revoked} (rather than dropping the host) keeps any pre-rotate
// token below that epoch rejected on this replica with no staleness window, while the just-minted current-epoch token verifies. A
// never-cycled host (epoch 0) carries no revocation state, so it is simply dropped from the map. Best-effort + per-replica: a concurrent
// refresh that read the pre-enroll row could momentarily disagree, but the next refresh reconciles to the DB; other replicas converge on
// their own refresh.
func (s *Snapshot) Observe(hostID string, epoch int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if epoch <= 0 {
		delete(s.entries, hostID)
		return
	}
	s.entries[hostID] = Entry{HostID: hostID, Epoch: epoch, Revoked: false}
}

// Refresh reloads the snapshot from the source. On error the previous snapshot is retained (stale is better than empty: dropping to
// empty would briefly un-revoke every cut-off host) and the failure is counted + logged.
func (s *Snapshot) Refresh(ctx context.Context) error {
	rows, err := s.src.RevocationEntries(ctx)
	if err != nil {
		if s.refreshFailures != nil {
			s.refreshFailures.Add(ctx, 1)
		}
		s.logger.WarnContext(ctx, "revocation snapshot refresh failed; serving previous snapshot", "err", err)
		return err
	}
	next := make(map[string]Entry, len(rows))
	for _, r := range rows {
		next[r.HostID] = r
	}
	s.mu.Lock()
	s.entries = next
	s.mu.Unlock()
	s.lastRefreshUnix.Store(time.Now().Unix())
	return nil
}

// Run refreshes once immediately, then on every interval tick until ctx is cancelled. The initial refresh error is logged but not
// fatal: the ticker retries, and an empty snapshot fails open (allows tokens) only until the first successful load, which is the same
// availability posture the rest of the auth path takes on a transient DB blip.
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
