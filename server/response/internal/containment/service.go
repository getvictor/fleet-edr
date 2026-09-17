// Package containment is the server's half of host network containment (#948): each host's desired state, the operator change that
// records it, its delivery as a set_network_containment command, and the catch-up that re-queues it for hosts that missed it.
package containment

import (
	"github.com/jmoiron/sqlx"

	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"unicode/utf8"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
)

// CommandQueuer queues one command for a host through an existing transaction and returns its id, so a state and the command
// carrying it are recorded together (issue #1073).
type CommandQueuer func(ctx context.Context, q sqlx.ExecerContext, hostID, commandType string, payload []byte) (int64, error)

// Notifier tells the control gateway a host has a command waiting. Called after the transaction that queued it has committed.
type Notifier func(hostID string)

// LatestCommands returns each host's most recently queued command of a type; hosts with none are absent.
type LatestCommands func(ctx context.Context, commandType string, hostIDs []string) (map[string]api.Command, error)

// Service records containment changes and reads a host's state.
type Service struct {
	store    *Store
	enrolled api.HostEnrolledChecker
	queue    CommandQueuer
	notify   Notifier
	latest   LatestCommands
	audit    identityapi.AuditRecorder
	logger   *slog.Logger
}

// NewService builds a Service. store, enrolled, insert and latest are required. audit may be nil outside production, which records
// changes without audit events.
func NewService(store *Store, enrolled api.HostEnrolledChecker, queue CommandQueuer, notify Notifier, latest LatestCommands,
	audit identityapi.AuditRecorder, logger *slog.Logger) *Service {
	if store == nil || enrolled == nil || queue == nil || notify == nil || latest == nil {
		panic("containment.NewService: store, enrolled, queue, notify and latest are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{store: store, enrolled: enrolled, queue: queue, notify: notify, latest: latest, audit: audit, logger: logger}
}

// commandPayload is the set_network_containment payload for a state. The change and the catch-up both build it here, so a host that is
// caught up gets exactly what the change queued. Marshalling a struct of integers and a bool cannot fail.
func commandPayload(state api.ContainmentState) []byte {
	payload, _ := json.Marshal(api.SetNetworkContainmentPayload{Version: state.Version, Epoch: state.Epoch, Contained: state.Contained})
	return payload
}

// carries reports whether a command's payload delivers state. A host's version and epoch identify one state, so they are compared and
// nothing else.
func carries(cmd api.Command, state api.ContainmentState) bool {
	var queued api.SetNetworkContainmentPayload
	return json.Unmarshal(cmd.Payload, &queued) == nil && queued.Version == state.Version && queued.Epoch == state.Epoch
}

// Get returns a host's state with its delivery.
func (s *Service) Get(ctx context.Context, hostID string) (api.ContainmentState, error) {
	state, err := s.store.Get(ctx, hostID)
	if err != nil || state.Version == 0 {
		// A host with no state has nothing to deliver, whatever set_network_containment commands were queued for it by other means.
		return state, err
	}
	latest, err := s.latest(ctx, api.CommandTypeSetNetworkContainment, []string{hostID})
	if err != nil {
		return api.ContainmentState{}, err
	}
	if cmd, ok := latest[hostID]; ok {
		state.Delivery = deliveryOf(cmd, state)
	}
	return state, nil
}

func deliveryOf(cmd api.Command, state api.ContainmentState) *api.ContainmentDelivery {
	return &api.ContainmentDelivery{CommandID: cmd.ID, Status: cmd.Status, Result: cmd.Result, Current: carries(cmd, state)}
}

// List returns every host that has a containment state, with its delivery, in host_id order. A host whose containment was released
// is included: its state says so, and its delivery says whether the release reached it.
func (s *Service) List(ctx context.Context) ([]api.ContainmentState, error) {
	states, err := s.store.All(ctx)
	if err != nil || len(states) == 0 {
		return states, err
	}
	hostIDs := make([]string, len(states))
	for i, state := range states {
		hostIDs[i] = state.HostID
	}
	latest, err := s.latest(ctx, api.CommandTypeSetNetworkContainment, hostIDs)
	if err != nil {
		return nil, err
	}
	for i := range states {
		if cmd, ok := latest[states[i].HostID]; ok {
			states[i].Delivery = deliveryOf(cmd, states[i])
		}
	}
	return states, nil
}

// Set asks for a host to be contained or released. A change is recorded, queued for the host and audited; a request for the state the
// host already has changes nothing. The state and its command are written in one transaction under the host's lock, so the commands
// queued for a host are in the order of the states they carry, and a change whose command cannot be queued records nothing and is
// refused rather than leaving a state for the catch-up to notice (issue #1073).
func (s *Service) Set(ctx context.Context, actor identityapi.PrincipalRef, remoteAddr, hostID string, contained bool,
	reason string) (api.ContainmentChange, error) {
	// The limit applies to the reason as sent, as the API schema states it; the recorded reason is the trimmed one.
	switch {
	case utf8.RuneCountInString(reason) > api.MaxContainmentReasonLength:
		return api.ContainmentChange{}, api.ErrContainmentReasonTooLong
	case strings.TrimSpace(reason) == "":
		return api.ContainmentChange{}, api.ErrContainmentReasonRequired
	}
	reason = strings.TrimSpace(reason)
	enrolled, err := s.enrolled(ctx, hostID)
	if err != nil {
		return api.ContainmentChange{}, err
	}
	if !enrolled {
		return api.ContainmentChange{}, api.ErrContainmentHostNotFound
	}
	// The command is queued inside the transaction that records the state, so a change that cannot queue one records nothing: the
	// operator is told it failed rather than left with a state whose command the catch-up has to notice (issue #1073).
	state, changed, commandID, err := s.store.Set(ctx, hostID, contained, reason, actor.ID,
		func(ctx context.Context, q sqlx.ExecerContext, state api.ContainmentState) (int64, error) {
			return s.queue(ctx, q, hostID, api.CommandTypeSetNetworkContainment, commandPayload(state))
		})
	if err != nil {
		return api.ContainmentChange{}, err
	}
	change := api.ContainmentChange{State: state, Changed: changed, CommandID: commandID}
	if !changed {
		return change, nil
	}
	// After the commit: a gateway told earlier could look for a command that is not there yet.
	s.notify(hostID)
	s.recordAudit(ctx, actor, remoteAddr, change)
	return change, nil
}

// recordAudit emits the change's audit event. The state row is authoritative, so a recorder failure is logged rather than returned,
// as for command issuance.
func (s *Service) recordAudit(ctx context.Context, actor identityapi.PrincipalRef, remoteAddr string, change api.ContainmentChange) {
	if s.audit == nil {
		return
	}
	action := identityapi.AuditHostRelease
	if change.State.Contained {
		action = identityapi.AuditHostContain
	}
	payload := map[string]any{"reason": change.State.Reason, "version": change.State.Version, "epoch": change.State.Epoch}
	if change.CommandID != 0 {
		payload["command_id"] = change.CommandID
	}
	if err := s.audit.Record(ctx, identityapi.AuditEvent{
		Actor: actor, Action: action, TargetType: "host", TargetID: change.State.HostID, RemoteAddr: remoteAddr, Payload: payload,
	}); err != nil {
		s.logger.WarnContext(ctx, "audit record", "err", err, "action", string(action), "host_id", change.State.HostID)
	}
}
