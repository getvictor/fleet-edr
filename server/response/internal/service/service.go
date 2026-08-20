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

// PendingCommandTTL is how long a command may wait for delivery before it is aged out instead of being handed to an agent.
//
// A command can sit pending indefinitely when a host is offline or is holding a control stream the server has forgotten (issue #711).
// That is not merely stale: kill_process addresses a pid, pids are reused, and a kill delivered long after it was issued can terminate
// an unrelated process. An hour is far beyond any legitimate delivery delay (the push path is sub-second and the poll floor is
// minutes) while staying long enough that a host rebooting or briefly offline still gets its command.
const PendingCommandTTL = time.Hour

// Service implements api.Service. It composes the mysql.Store with an optional Heartbeat closure. Status-transition validation lives
// here (so the matrix is testable without a DB).
type Service struct {
	store     *mysql.Store
	heartbeat Heartbeat
	// notify is an optional per-replica fast-path hook the control gateway registers so a command queued on this replica reaches a
	// locally-held connection immediately instead of waiting for the gateway watch tick. It is a callback, not stored state; nil leaves
	// delivery to the gateway watch (and the agent poll fallback).
	notify func(hostID string)
	logger *slog.Logger
}

// SetNotifier registers the control-gateway fast-path callback. Called once at bootstrap, before serving, to break the
// service-then-gateway construction cycle. Safe to leave unset: delivery then relies on the gateway's 1s watch and the poll fallback.
func (s *Service) SetNotifier(notify func(hostID string)) { s.notify = notify }

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
	id, err := s.store.Insert(ctx, hostID, commandType, payload)
	if err == nil {
		s.fastNotify(hostID)
	}
	return id, err
}

// fastNotify signals the control gateway (if registered) that a host has freshly-queued work, for immediate push.
func (s *Service) fastNotify(hostID string) {
	if s.notify != nil {
		s.notify(hostID)
	}
}

// InsertBatch validates the shared commandType + payload once, then enqueues one command row per host via the store's chunked
// multi-row INSERT. It is the application-control fan-out's enqueue path; returns the number of rows that landed.
//
// An empty hostIDs slice, an empty commandType, or an empty payload all wrap ErrInvalidInsertRequest so callers can errors.Is +
// map to 400. commandType is trimmed once at the boundary, matching Insert. Unlike Insert, the individual host_ids are NOT
// trimmed: the only caller sources them from the host store's primary keys (already clean), so trimming each would be dead
// defensive work; a malformed entry surfaces as a store error rather than being silently dropped, which would understate the
// fan-out count.
func (s *Service) InsertBatch(ctx context.Context, hostIDs []string, commandType string, payload []byte) (int, error) {
	if len(hostIDs) == 0 {
		return 0, fmt.Errorf("%w: at least one host_id is required", api.ErrInvalidInsertRequest)
	}
	commandType = strings.TrimSpace(commandType)
	if commandType == "" {
		return 0, fmt.Errorf("%w: command_type is required", api.ErrInvalidInsertRequest)
	}
	if len(payload) == 0 {
		return 0, fmt.Errorf("%w: payload is required", api.ErrInvalidInsertRequest)
	}
	n, err := s.store.InsertBatch(ctx, hostIDs, commandType, payload)
	if err == nil {
		for _, h := range hostIDs {
			s.fastNotify(h)
		}
	}
	return n, err
}

// Get returns a single command by id.
func (s *Service) Get(ctx context.Context, id int64) (api.Command, error) {
	return s.store.Get(ctx, id)
}

// ListForHost returns the host's commands and (best-effort) bumps the host's last-seen-ns via the Heartbeat closure. A heartbeat error
// is logged at WARN and ignored; the agent already got its commands and the next poll re-tries.
func (s *Service) ListForHost(ctx context.Context, hostID string, status api.Status) ([]api.Command, error) {
	// Age out anything past the delivery window before answering, so a stale command is never handed to an agent. A kill_process
	// addresses a pid and pids are reused, so delivering one issued long ago can terminate an unrelated process (issue #711). Scoped
	// to this host, and only on the pending read, which is the delivery path: an operator listing history still sees every command.
	if status == api.StatusPending {
		if n, err := s.store.ExpirePendingOlderThan(ctx, hostID, time.Now().Add(-PendingCommandTTL)); err != nil {
			// Not fatal: failing to age out is worse than not answering, so log and fall through to the read, which simply may still
			// include a stale command this once.
			s.logger.WarnContext(ctx, "expire stale commands", "host_id", hostID, "err", err)
		} else if n > 0 {
			s.logger.InfoContext(ctx, "aged out commands never delivered", "host_id", hostID, "count", n)
		}
	}
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

// ListPendingForHosts returns every pending command queued for the given hosts. Unlike ListForHost it does NOT bump last-seen: the
// caller is the control gateway, whose connection presence (not this query) is the liveness signal. Used by the gateway's watch loop
// and its per-host fast path to push queued work to connected agents.
func (s *Service) ListPendingForHosts(ctx context.Context, hostIDs []string) ([]api.Command, error) {
	return s.store.ListPendingForHosts(ctx, hostIDs)
}

// UpdateStatus enforces the status-transition matrix on top of the store's row write. Loads the current row to validate ownership +
// current status before persisting; collapses both "wrong host" and "unknown id" to api.ErrCommandNotFound at the boundary.
func (s *Service) UpdateStatus(ctx context.Context, req api.UpdateStatusRequest) error {
	if !validTargetStatus(req.Status) {
		return fmt.Errorf("%w: status must be acked, completed, failed, cancelled, or expired (got %q)",
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
	case api.StatusAcked, api.StatusCompleted, api.StatusFailed, api.StatusCancelled, api.StatusExpired:
		return true
	}
	return false
}

// canTransition encodes the lifecycle matrix:
//
//	pending -> acked              (agent picked it up)
//	pending -> failed             (agent immediately rejected)
//	pending -> cancelled          (operator withdrew it before any agent saw it)
//	pending -> expired            (aged out before any agent picked it up)
//	acked   -> completed          (agent applied successfully)
//	acked   -> failed             (agent applied with errors)
//
// Every other transition is illegal: terminal states (completed, failed,
// cancelled) are immutable; transitioning back to pending is never
// permitted. Notably acked -> cancelled and acked -> expired are NOT
// permitted: once an agent
// has the command it may already have applied the side effect, so
// recording it as cancelled would misreport what happened on the host.
func canTransition(from, to api.Status) bool {
	switch from { //nolint:exhaustive // completed/failed are terminal; default returns false.
	case api.StatusPending:
		return to == api.StatusAcked || to == api.StatusFailed || to == api.StatusCancelled || to == api.StatusExpired
	case api.StatusAcked:
		return to == api.StatusCompleted || to == api.StatusFailed
	}
	return false
}
