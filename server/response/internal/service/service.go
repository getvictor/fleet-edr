package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/auditoutbox"
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
	// outbox is where an operator action commits the audit entry recording it, and drain turns the entries into audit rows
	// (issue #1070). The two nils mean different things and production sets both: with no drain an action still commits its entry
	// and the entry waits in the outbox, while with no outbox the action commits with nothing recording it, which is why only a
	// test that does not care about audit leaves the outbox unset. bootstrap.New always installs one.
	outbox *auditoutbox.Store
	drain  *auditoutbox.Drain
	logger *slog.Logger
}

// SetAuditOutbox installs the outbox an operator action commits its audit entry into and the drain that delivers it. Called once at
// bootstrap, before serving, for the same reason SetNotifier is: the drain needs the recorder, which is another context's.
func (s *Service) SetAuditOutbox(outbox *auditoutbox.Store, drain *auditoutbox.Drain) {
	s.outbox, s.drain = outbox, drain
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
	hostID, commandType, err := insertable(hostID, commandType, payload)
	if err != nil {
		return 0, err
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
	// The host list is this path's own check; what a command carries is the same question on every path.
	if len(hostIDs) == 0 {
		return 0, fmt.Errorf("%w: at least one host_id is required", api.ErrInvalidInsertRequest)
	}
	commandType, err := queueable(commandType, payload)
	if err != nil {
		return 0, err
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

// QueueTx queues a command through an existing transaction and returns its id. It deliberately does NOT notify the control gateway:
// nothing outside the transaction may be told about a command that is not committed yet, so the caller notifies with Notify once it
// has committed (issue #1073).
func (s *Service) QueueTx(ctx context.Context, q sqlx.ExecerContext, hostID, commandType string, payload []byte) (int64, error) {
	hostID, commandType, err := insertable(hostID, commandType, payload)
	if err != nil {
		return 0, err
	}
	return mysql.InsertTx(ctx, q, hostID, commandType, payload)
}

// AuditedCommand is the command row an operator action has just written, as the audit entry describing it must see it: normalized
// exactly as persisted, so the row and the entry cannot disagree about which host was affected. A caller that captured its own
// request values instead would record " host-a " for a command stored against host-a.
type AuditedCommand struct {
	ID          int64
	HostID      string
	CommandType string
}

// AuditEntryFor builds the audit entry recording an operator action on the command that has just been written. It runs inside the
// action's transaction, so an error from it refuses the action rather than leaving it recorded without a row.
type AuditEntryFor func(cmd AuditedCommand) (auditoutbox.Entry, error)

// InsertAudited queues a command and commits entry(id) with it, so an issued command and the row saying who issued it exist together
// or not at all (issue #1070). The gateway is notified and the entry delivered after the commit, in that order, because nothing
// outside the transaction may be told about a command that is not committed yet.
func (s *Service) InsertAudited(ctx context.Context, hostID, commandType string, payload []byte,
	entry AuditEntryFor) (int64, error) {
	hostID, commandType, err := insertable(hostID, commandType, payload)
	if err != nil {
		return 0, err
	}
	var id int64
	if err := s.store.InTx(ctx, func(q sqlx.ExtContext) error {
		id, err = mysql.InsertTx(ctx, q, hostID, commandType, payload)
		if err != nil {
			return err
		}
		return s.enqueueAudit(ctx, q, entry, AuditedCommand{ID: id, HostID: hostID, CommandType: commandType})
	}); err != nil {
		return 0, err
	}
	s.fastNotify(hostID)
	s.drain.DeliverNow(ctx)
	return id, nil
}

// UpdateStatusAudited moves a command and commits entry(id) with the move, for the operator paths that have to say who made it. The
// transition matrix is checked first, as in UpdateStatus, so an illegal move is refused before anything is written.
func (s *Service) UpdateStatusAudited(ctx context.Context, req api.UpdateStatusRequest, entry AuditEntryFor) error {
	current, err := s.transitionFrom(ctx, req)
	if err != nil {
		return err
	}
	if err := s.store.InTx(ctx, func(q sqlx.ExtContext) error {
		if err := mysql.UpdateStatusTx(ctx, q, req.ID, req.HostID, current.Status, req.Status, req.Result); err != nil {
			return err
		}
		// The command as stored, read back by transitionFrom, rather than as the request named it.
		return s.enqueueAudit(ctx, q, entry, AuditedCommand{ID: current.ID, HostID: current.HostID, CommandType: current.CommandType})
	}); err != nil {
		return err
	}
	s.drain.DeliverNow(ctx)
	return nil
}

// enqueueAudit builds the entry for the command just written and commits it through the same executor.
//
// A nil builder is refused rather than treated as a no-audit mode: these methods exist to guarantee the entry commits with the
// change, so silently committing one without the other would be the guarantee quietly not holding. A Service with no outbox is
// different, and is the non-production wiring described on the field.
func (s *Service) enqueueAudit(ctx context.Context, q sqlx.ExtContext, entry AuditEntryFor, cmd AuditedCommand) error {
	if entry == nil {
		return errors.New("response service: an audited write needs an audit entry builder")
	}
	if s.outbox == nil {
		return nil
	}
	e, err := entry(cmd)
	if err != nil {
		return err
	}
	return s.outbox.Enqueue(ctx, q, e)
}

// insertable normalizes and checks what a command queued for one host needs, so the transactional path cannot drift from the
// ordinary one.
func insertable(hostID, commandType string, payload []byte) (string, string, error) {
	hostID = strings.TrimSpace(hostID)
	if hostID == "" {
		return "", "", fmt.Errorf("%w: host_id is required", api.ErrInvalidInsertRequest)
	}
	commandType, err := queueable(commandType, payload)
	if err != nil {
		return "", "", err
	}
	return hostID, commandType, nil
}

// queueable normalizes and checks what every queued command carries, whoever queues it: one host, a batch of them, or a caller
// holding a transaction.
func queueable(commandType string, payload []byte) (string, error) {
	commandType = strings.TrimSpace(commandType)
	if commandType == "" {
		return "", fmt.Errorf("%w: command_type is required", api.ErrInvalidInsertRequest)
	}
	if len(payload) == 0 {
		return "", fmt.Errorf("%w: payload is required", api.ErrInvalidInsertRequest)
	}
	return commandType, nil
}

// Notify tells the control gateway a host has a command waiting, for a caller that queued one through QueueTx and has committed.
func (s *Service) Notify(hostID string) {
	s.fastNotify(hostID)
}

// ListDeliverableForHosts returns everything the given hosts are owed: their pending commands, and the ones they acknowledged inside
// the window whose outcome never arrived, which the gateway offers again so the agent can replay it (issue #1062). Unlike ListForHost
// it does NOT bump last-seen: the connection is the liveness signal, not this read.
func (s *Service) ListDeliverableForHosts(ctx context.Context, hostIDs []string, ackedAfter,
	ackedBefore time.Time) ([]api.Command, error) {
	return s.store.ListDeliverableForHosts(ctx, hostIDs, ackedAfter, ackedBefore)
}

// UpdateStatus enforces the status-transition matrix on top of the store's row write. Loads the current row to validate ownership +
// current status before persisting; collapses both "wrong host" and "unknown id" to api.ErrCommandNotFound at the boundary.
func (s *Service) UpdateStatus(ctx context.Context, req api.UpdateStatusRequest) error {
	current, err := s.transitionFrom(ctx, req)
	if err != nil {
		return err
	}
	// Pass the stored status as the expected-from value so the store applies the WHERE clause atomically. If a concurrent caller
	// advanced the row between our read and this write, the store returns ErrInvalidStatusTransition rather than silently
	// overwriting the newer state.
	return s.store.UpdateStatus(ctx, req.ID, req.HostID, current.Status, req.Status, req.Result)
}

// transitionFrom checks that req is a move this command may make and returns the command as stored. Its status is what the write pins
// in its WHERE clause, and its host and type are what an audit entry describes, so neither is taken from the request. Shared with
// UpdateStatusAudited so an audited move cannot drift from an unaudited one.
func (s *Service) transitionFrom(ctx context.Context, req api.UpdateStatusRequest) (api.Command, error) {
	if !validTargetStatus(req.Status) {
		return api.Command{}, fmt.Errorf("%w: status must be acked, completed, failed, cancelled, or expired (got %q)",
			api.ErrInvalidStatusTransition, req.Status)
	}
	// Load the current row to validate ownership + current state. store.Get returns ErrCommandNotFound when the id is unknown;
	// we additionally collapse the wrong-host case to the same sentinel (probing-oracle defence).
	current, err := s.store.Get(ctx, req.ID)
	if err != nil {
		return api.Command{}, err
	}
	if current.HostID != req.HostID {
		return api.Command{}, api.ErrCommandNotFound
	}
	if !canTransition(current.Status, req.Status) {
		return api.Command{}, fmt.Errorf("%w: cannot move from %q to %q",
			api.ErrInvalidStatusTransition, current.Status, req.Status)
	}
	return current, nil
}

// UndeliverableByHost reports which of hostIDs have commands that aged out undelivered recently (issue #732). The window boundary is
// computed here rather than in the store, so the policy (api.UndeliverableWindow) sits with the service that owns it.
func (s *Service) UndeliverableByHost(ctx context.Context, hostIDs []string) (map[string]api.Undeliverable, error) {
	return s.store.UndeliverableByHost(ctx, hostIDs, time.Now().Add(-api.UndeliverableWindow))
}

// LatestOfType returns each host's most recently queued command of commandType. A pass-through: which command counts as latest (the
// highest id, the order commands were queued in) is the store's query.
func (s *Service) LatestOfType(ctx context.Context, commandType string, hostIDs []string) (map[string]api.Command, error) {
	return s.store.LatestOfType(ctx, commandType, hostIDs)
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
//	cancelled -> acked            (it had already been delivered; the record corrects to what ran)
//	expired   -> acked            (same, for one aged out while in flight)
//	acked   -> completed          (agent applied successfully)
//	acked   -> failed             (agent applied with errors)
//
// Every other transition is illegal: terminal states (completed, failed,
// cancelled) are immutable; transitioning back to pending is never
// permitted, except that a late ack may reopen a cancelled or expired
// command (see below). Notably acked -> cancelled and acked -> expired
// are NOT permitted: once an agent
// has the command it may already have applied the side effect, so
// recording it as cancelled would misreport what happened on the host.
func canTransition(from, to api.Status) bool {
	switch from { //nolint:exhaustive // completed/failed are terminal; default returns false.
	case api.StatusPending:
		return to == api.StatusAcked || to == api.StatusFailed || to == api.StatusCancelled || to == api.StatusExpired
	case api.StatusCancelled, api.StatusExpired:
		// Withdrawal races delivery. The gateway pushes a command while its row is still pending, and the agent starts the side
		// effect and acks asynchronously, so a cancel can land in the window before that ack is persisted. Leaving these terminal
		// would then record "nothing ran" for a command that DID run, which is the precise misreport this whole feature exists to
		// prevent, so a late ack is allowed to correct the record. Cancelling is therefore a request that wins only if the agent had
		// not already taken the command, not a guarantee that it never runs. Only acked is reachable: the agent always acks before
		// its terminal report, so the rest of the lifecycle stays as it was.
		return to == api.StatusAcked
	case api.StatusAcked:
		return to == api.StatusCompleted || to == api.StatusFailed
	}
	return false
}
