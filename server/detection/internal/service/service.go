package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/intake"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
)

// UserExists is the closure cmd/main wires from
// identity.api.Service.UserExists. PUT /api/alerts/{id} calls it
// before persisting `updated_by` so the FK that phase 5 dropped
// doesn't silently let orphan user_ids land on the row.
type UserExists func(ctx context.Context, userID int64) (bool, error)

// Service is the operator-facing detection orchestrator. Composes
// graph.Query (reads), mysql.Store (alert reads + writes), and the
// UserExists closure (FK-replacement for alerts.updated_by).
type Service struct {
	store      *mysql.Store
	query      *graph.Query
	intakeH    *intake.Handler
	userExists UserExists
	logger     *slog.Logger
}

// New builds a Service. Any of the inputs may be nil for limited
// modes (intake-only mode passes nil for query / userExists).
func New(
	s *mysql.Store,
	q *graph.Query,
	intakeH *intake.Handler,
	userExists UserExists,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		store:      s,
		query:      q,
		intakeH:    intakeH,
		userExists: userExists,
		logger:     logger,
	}
}

// ListHosts returns the per-host activity summary.
func (s *Service) ListHosts(ctx context.Context) ([]api.HostSummary, error) {
	return s.query.ListHosts(ctx)
}

// BuildTree returns a forest of process trees for the host + window.
func (s *Service) BuildTree(ctx context.Context, hostID string, tr api.TimeRange, limit int) ([]api.ProcessNode, error) {
	return s.query.BuildTree(ctx, hostID, tr, limit)
}

// GetProcessDetail returns a process with its network connections,
// DNS queries, and re-exec chain.
func (s *Service) GetProcessDetail(ctx context.Context, hostID string, pid int, atTimeNs int64) (*api.ProcessDetail, error) {
	return s.query.GetProcessDetail(ctx, hostID, pid, atTimeNs)
}

// ListAlerts returns alerts matching the filter.
func (s *Service) ListAlerts(ctx context.Context, filter api.AlertFilter) ([]api.Alert, error) {
	return s.store.ListAlerts(ctx, filter)
}

// GetAlert returns a single alert by id along with its correlated
// event_ids.
func (s *Service) GetAlert(ctx context.Context, id int64) (api.Alert, []string, error) {
	alert, err := s.store.GetAlert(ctx, id)
	if err != nil {
		return api.Alert{}, nil, err
	}
	eventIDs, err := s.store.GetAlertEventIDs(ctx, id)
	if err != nil {
		return api.Alert{}, nil, fmt.Errorf("get alert event ids %d: %w", id, err)
	}
	return alert, eventIDs, nil
}

// UpdateAlertStatus enforces the lifecycle matrix and validates
// updated_by via the UserExists closure (the FK-replacement check).
//
// Lifecycle matrix:
//
//	open         -> acknowledged
//	open         -> resolved
//	acknowledged -> open  (operator un-acknowledges)
//	acknowledged -> resolved
//	resolved     -> open  (operator reopens)
//
// All other transitions return ErrInvalidAlertTransition.
func (s *Service) UpdateAlertStatus(ctx context.Context, id int64, status api.AlertStatus, userID int64) (api.Alert, error) {
	current, err := s.store.GetAlert(ctx, id)
	if err != nil {
		return api.Alert{}, err
	}

	if !canTransition(current.Status, status) {
		return api.Alert{}, fmt.Errorf("%w: %s -> %s", api.ErrInvalidAlertTransition, current.Status, status)
	}

	// Validate updated_by user exists in the identity context.
	// Replaces the cross-context FK fk_alerts_updated_by that phase 5 drops.
	// userID == 0 means "internal backfill, leave updated_by alone" so the
	// existence check is skipped.
	if userID > 0 && s.userExists != nil {
		exists, err := s.userExists(ctx, userID)
		if err != nil {
			return api.Alert{}, fmt.Errorf("validate updated_by user %d: %w", userID, err)
		}
		if !exists {
			return api.Alert{}, fmt.Errorf("%w: user_id=%d", api.ErrInvalidUserUpdater, userID)
		}
	}

	if err := s.store.UpdateAlertStatus(ctx, id, status, userID); err != nil {
		return api.Alert{}, err
	}
	updated, err := s.store.GetAlert(ctx, id)
	if err != nil {
		return api.Alert{}, err
	}
	return updated, nil
}

func canTransition(from, to api.AlertStatus) bool {
	switch from {
	case api.AlertStatusOpen:
		return to == api.AlertStatusAcknowledged || to == api.AlertStatusResolved
	case api.AlertStatusAcknowledged:
		return to == api.AlertStatusOpen || to == api.AlertStatusResolved
	case api.AlertStatusResolved:
		return to == api.AlertStatusOpen
	}
	return false
}

// RecordHostSeen advances hosts.last_seen_ns. Called by response on
// every /api/commands poll; replaces store.UpdateHostLastSeen.
func (s *Service) RecordHostSeen(ctx context.Context, hostID string, at time.Time) error {
	return s.store.UpdateHostLastSeen(ctx, hostID, at)
}

// CountOfflineHosts counts hosts whose last_seen_ns is older than
// the threshold.
func (s *Service) CountOfflineHosts(ctx context.Context, threshold time.Duration) (int, error) {
	return s.store.CountOfflineHosts(ctx, threshold)
}

// CountUnprocessed counts events with processed != 1.
func (s *Service) CountUnprocessed(ctx context.Context) (int64, error) {
	return s.store.CountUnprocessed(ctx)
}

// IngestHandler returns the POST /api/events handler. cmd/main mounts
// it under endpoint.HostToken middleware.
func (s *Service) IngestHandler() http.Handler {
	if s.intakeH == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "intake not configured", http.StatusServiceUnavailable)
		})
	}
	return s.intakeH.IngestHandler()
}
