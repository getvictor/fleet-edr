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
	identityapi "github.com/fleetdm/edr/server/identity/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// UserExists is the closure cmd/main wires from identity.api.Service.UserExists. PUT /api/alerts/{id} calls it before persisting
// `updated_by` so that orphan user_ids cannot silently land on the row in the absence of a cross-context FK.
type UserExists func(ctx context.Context, userID int64) (bool, error)

// Service is the operator-facing detection orchestrator. Composes graph.Query (reads), mysql.Store (alert reads + writes), and the
// UserExists closure (FK-replacement for alerts.updated_by).
type Service struct {
	store      *mysql.Store
	query      *graph.Query
	intakeH    *intake.Handler
	eventLog   visibilityapi.EventLog
	userExists UserExists
	logger     *slog.Logger
}

// New builds a Service. Any of the inputs may be nil for limited
// modes (intake-only mode passes nil for query / userExists).
func New(
	s *mysql.Store,
	q *graph.Query,
	intakeH *intake.Handler,
	eventLog visibilityapi.EventLog,
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
		eventLog:   eventLog,
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

// GetAlertEvidence returns the self-contained triggering-event envelopes captured for an alert at creation time (ADR-0015).
func (s *Service) GetAlertEvidence(ctx context.Context, id int64) ([]api.Event, error) {
	return s.store.GetAlertEventPayloads(ctx, id)
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
func (s *Service) UpdateAlertStatus(ctx context.Context, id int64, status api.AlertStatus, actorID string) (api.Alert, error) {
	current, err := s.store.GetAlert(ctx, id)
	if err != nil {
		return api.Alert{}, err
	}

	if !canTransition(current.Status, status) {
		return api.Alert{}, fmt.Errorf("%w: %s -> %s", api.ErrInvalidAlertTransition, current.Status, status)
	}

	// For a human actor, validate the user still exists in the identity context (alerts.updated_by has no cross-context FK, ADR-0004).
	// A service-account or system principal is trusted from the authenticated actor and skips the check; an empty actor ("" = internal
	// backfill) leaves updated_by alone.
	if uid, ok := (identityapi.PrincipalRef{ID: actorID}).UserID(); ok && s.userExists != nil {
		exists, err := s.userExists(ctx, uid)
		if err != nil {
			return api.Alert{}, fmt.Errorf("validate updated_by user %d: %w", uid, err)
		}
		if !exists {
			return api.Alert{}, fmt.Errorf("%w: principal=%s", api.ErrInvalidUserUpdater, actorID)
		}
	}

	if err := s.store.UpdateAlertStatus(ctx, id, status, actorID); err != nil {
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

// CountUnprocessed counts events not yet fully processed: the visibility EventLog work-queue backlog (ADR-0015). Backs the OTel
// unprocessed-events gauge so SOC dashboards alert on a stuck processor; the queue, not the durable archive, is the backlog.
func (s *Service) CountUnprocessed(ctx context.Context) (int64, error) {
	return s.eventLog.CountPending(ctx)
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
