package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/response/api"
	"github.com/fleetdm/edr/server/response/internal/mysql"
)

// Service implements api.Service. It composes the mysql.Store with an optional Heartbeat closure. Status-transition validation lives
// here (so the matrix is testable without a DB).
type Service struct {
	store     *mysql.Store
	heartbeat Heartbeat
	logger    *slog.Logger
}

// New builds a Service. store must be non-nil; heartbeat may be nil (tests that don't care about the per-poll last-seen bump pass nil
// and ListForHost skips the call).
func New(store *mysql.Store, heartbeat Heartbeat, logger *slog.Logger) *Service {
	if store == nil {
		panic("response service.New: store must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		store:     store,
		heartbeat: heartbeat,
		logger:    logger,
	}
}

// Insert validates the request shape, then delegates to the store.
// Empty hostID / commandType / payload all wrap
// ErrInvalidInsertRequest so callers can errors.Is + map to 400.
//
// hostID and commandType are trimmed once at the boundary; the
// trimmed values land in the row so a stray operator-typed space
// can't produce a host_id with trailing whitespace that then fails
// every ListForHost lookup.
func (s *Service) Insert(ctx context.Context, hostID, commandType string, payload []byte) (int64, error) {
	hostID = strings.TrimSpace(hostID)
	if hostID == "" {
		return 0, fmt.Errorf("%w: host_id is required", api.ErrInvalidInsertRequest)
	}
	commandType = strings.TrimSpace(commandType)
	if commandType == "" {
		return 0, fmt.Errorf("%w: command_type is required", api.ErrInvalidInsertRequest)
	}
	if len(payload) == 0 {
		return 0, fmt.Errorf("%w: payload is required", api.ErrInvalidInsertRequest)
	}
	return s.store.Insert(ctx, hostID, commandType, payload)
}

// Get returns a single command by id.
func (s *Service) Get(ctx context.Context, id int64) (api.Command, error) {
	return s.store.Get(ctx, id)
}

// ListForHost returns the host's commands and (best-effort) bumps the host's last-seen-ns via the Heartbeat closure. A heartbeat error
// is logged at WARN and ignored; the agent already got its commands and the next poll re-tries.
func (s *Service) ListForHost(ctx context.Context, hostID string, status api.Status) ([]api.Command, error) {
	if s.heartbeat != nil {
		if err := s.heartbeat(ctx, hostID, time.Now()); err != nil {
			s.logger.WarnContext(ctx, "response heartbeat",
				attrkeys.HostID, hostID, "err", err)
		}
	}
	cmds, err := s.store.ListForHost(ctx, hostID, string(status))
	if err != nil {
		return nil, err
	}
	if cmds == nil {
		cmds = []api.Command{}
	}
	return cmds, nil
}

// UpdateStatus enforces the status-transition matrix on top of the store's row write. Loads the current row to validate ownership +
// current status before persisting; collapses both "wrong host" and "unknown id" to api.ErrCommandNotFound at the boundary.
func (s *Service) UpdateStatus(ctx context.Context, req api.UpdateStatusRequest) error {
	if !validTargetStatus(req.Status) {
		return fmt.Errorf("%w: status must be acked, completed, or failed (got %q)",
			api.ErrInvalidStatusTransition, req.Status)
	}

	// Load the current row to validate ownership + current state. store.Get returns ErrCommandNotFound when the id is unknown;
	// we additionally collapse the wrong-host case to the same sentinel (probing-oracle defence).
	current, err := s.store.Get(ctx, req.ID)
	if err != nil {
		return err
	}
	if current.HostID != req.HostID {
		return api.ErrCommandNotFound
	}
	if !canTransition(current.Status, req.Status) {
		return fmt.Errorf("%w: cannot move from %q to %q",
			api.ErrInvalidStatusTransition, current.Status, req.Status)
	}

	// Pass current.Status as the expected-from value so the store applies the WHERE clause atomically. If a concurrent caller advanced the
	// row between our read and this write, the store returns ErrInvalidStatusTransition (not silently overwriting the newer state).
	return s.store.UpdateStatus(ctx, req.ID, req.HostID, current.Status, req.Status, req.Result)
}

// CountPending delegates straight to the store.
func (s *Service) CountPending(ctx context.Context) (int, error) {
	return s.store.CountPending(ctx)
}

// validTargetStatus reports whether the agent-supplied status is a legal target for an UpdateStatus call. pending is rejected here
// because the agent must transition forward.
func validTargetStatus(s api.Status) bool {
	switch s { //nolint:exhaustive // pending is intentionally rejected; default falls through to false.
	case api.StatusAcked, api.StatusCompleted, api.StatusFailed:
		return true
	}
	return false
}

// canTransition encodes the lifecycle matrix:
//
//	pending -> acked              (agent picked it up)
//	pending -> failed             (agent immediately rejected)
//	acked   -> completed          (agent applied successfully)
//	acked   -> failed             (agent applied with errors)
//
// Every other transition is illegal -- terminal states (completed,
// failed) are immutable; transitioning back to pending is never
// permitted.
func canTransition(from, to api.Status) bool {
	switch from { //nolint:exhaustive // completed/failed are terminal; default returns false.
	case api.StatusPending:
		return to == api.StatusAcked || to == api.StatusFailed
	case api.StatusAcked:
		return to == api.StatusCompleted || to == api.StatusFailed
	}
	return false
}
