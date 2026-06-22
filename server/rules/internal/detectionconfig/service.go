package detectionconfig

import (
	"context"
	"sync/atomic"

	"github.com/fleetdm/edr/server/rules/api"
)

// Service is the live detection-config provider. It loads an immutable Snapshot from the Store and swaps it atomically on Reload, so
// rule evaluation (via api.ExclusionResolver) and the detection engine (via api.RuleModeResolver) always read a consistent
// point-in-time view without locks and without a restart. The snapshot is a per-replica cache, safe to lose (ADR-0010): each replica
// converges by reloading. Satisfies api.ExclusionResolver and api.RuleModeResolver.
type Service struct {
	store      *Store
	membership Membership
	snap       atomic.Pointer[Snapshot]
}

var (
	_ api.ExclusionResolver = (*Service)(nil)
	_ api.RuleModeResolver  = (*Service)(nil)
)

// NewService builds a Service seeded with an empty snapshot (excludes nothing, every rule alerts) so the resolver is safe to consult
// before the first Reload. membership decides whether a group-scoped record applies to a host; nil means only global records apply
// (the Phase A norm, since the only host group is the immutable all-hosts group).
func NewService(store *Store, membership Membership) *Service {
	s := &Service{store: store, membership: membership}
	s.snap.Store(NewSnapshot(0, nil, nil, membership, nil))
	return s
}

// Reload reads the current configuration from the store and atomically swaps the in-memory snapshot. Called once at boot (after the
// schema is applied), after every mutation through the REST surface, and by the periodic refresh that picks up another replica's
// changes.
func (s *Service) Reload(ctx context.Context) error {
	snap, err := s.store.LoadSnapshot(ctx, s.membership, nil)
	if err != nil {
		return err
	}
	s.snap.Store(snap)
	return nil
}

// Store returns the underlying store so the REST handler can mutate configuration and then call Reload.
func (s *Service) Store() *Store { return s.store }

// Version returns the snapshot version currently loaded in memory.
func (s *Service) Version() int64 { return s.snap.Load().Version() }

// Excluded implements api.ExclusionResolver against the current snapshot.
func (s *Service) Excluded(ruleID string, matchType api.ExclusionMatchType, value, hostID string) bool {
	return s.snap.Load().Excluded(ruleID, matchType, value, hostID)
}

// Mode implements api.RuleModeResolver against the current snapshot.
func (s *Service) Mode(ruleID, hostID string) api.DetectionRuleMode {
	return s.snap.Load().Mode(ruleID, hostID)
}

// SeverityOverride implements api.RuleModeResolver against the current snapshot.
func (s *Service) SeverityOverride(ruleID, hostID string) string {
	return s.snap.Load().SeverityOverride(ruleID, hostID)
}
