// Package containment is the server's half of host network containment (#948): each host's desired state, the operator change that
// records it, its delivery as a set_network_containment command, and the catch-up that re-queues it for hosts that missed it.
package containment

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"unicode/utf8"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
)

// CommandInserter queues one command for a host and returns its id.
type CommandInserter func(ctx context.Context, hostID, commandType string, payload []byte) (int64, error)

// LatestCommands returns each host's most recently queued command of a type; hosts with none are absent.
type LatestCommands func(ctx context.Context, commandType string, hostIDs []string) (map[string]api.Command, error)

// Service records containment changes and reads a host's state.
type Service struct {
	store    *Store
	enrolled api.HostEnrolledChecker
	insert   CommandInserter
	latest   LatestCommands
	audit    identityapi.AuditRecorder
	logger   *slog.Logger
}

// NewService builds a Service. store, enrolled, insert and latest are required. audit may be nil outside production, which records
// changes without audit events.
func NewService(store *Store, enrolled api.HostEnrolledChecker, insert CommandInserter, latest LatestCommands,
	audit identityapi.AuditRecorder, logger *slog.Logger) *Service {
	if store == nil || enrolled == nil || insert == nil || latest == nil {
		panic("containment.NewService: store, enrolled, insert and latest are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{store: store, enrolled: enrolled, insert: insert, latest: latest, audit: audit, logger: logger}
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
		state.Delivery = &api.ContainmentDelivery{CommandID: cmd.ID, Status: cmd.Status, Result: cmd.Result, Current: carries(cmd, state)}
	}
	return state, nil
}

// Set asks for a host to be contained or released. A change is recorded, queued for the host and audited; a request for the state the
// host already has changes nothing. The recorded state is authoritative once written, so a command that could not be queued does not
// fail the change: the response carries no command id and the catch-up queues it.
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
	state, changed, err := s.store.Set(ctx, hostID, contained, reason, actor.ID)
	if err != nil {
		return api.ContainmentChange{}, err
	}
	change := api.ContainmentChange{State: state, Changed: changed}
	if !changed {
		return change, nil
	}
	if change.CommandID, err = s.insert(ctx, hostID, api.CommandTypeSetNetworkContainment, commandPayload(state)); err != nil {
		s.logger.WarnContext(ctx, "containment: recorded but not queued; the catch-up will queue it", "host_id", hostID,
			"version", state.Version, "err", err)
	}
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
