// Package containment is the server's half of host network containment (#948): each host's desired state, the operator change that
// records it, its delivery as a set_network_containment command, and the catch-up that re-queues it for hosts that missed it.
package containment

import (
	"github.com/jmoiron/sqlx"

	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/fleetdm/edr/server/auditoutbox"
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
	outbox   *auditoutbox.Store
	drain    *auditoutbox.Drain
	// reachable reads the destinations a contained host may still reach. Every command carries the set, so a change to it reaches
	// hosts through the catch-up rather than through a command of its own (issue #1059).
	reachable ReachableSet
}

// NewService builds a Service. store, enrolled, queue, notify, latest and outbox are required: the outbox is where a change's audit
// entry commits with it, so a Service without one could record a containment with nothing saying who made it. drain may be nil outside
// production, which leaves the entries in the outbox rather than turning them into audit rows.
func NewService(store *Store, enrolled api.HostEnrolledChecker, queue CommandQueuer, notify Notifier, latest LatestCommands,
	outbox *auditoutbox.Store, drain *auditoutbox.Drain, reachable ReachableSet) *Service {
	if store == nil || enrolled == nil || queue == nil || notify == nil || latest == nil || outbox == nil || reachable == nil {
		panic("containment.NewService: store, enrolled, queue, notify, latest, outbox and reachable are required")
	}
	return &Service{store: store, enrolled: enrolled, queue: queue, notify: notify, latest: latest, outbox: outbox, drain: drain,
		reachable: reachable}
}

// ReachableSet reads the deployment's reachable-address set, which every containment command carries (issue #1059). Injected rather
// than imported so this package keeps deciding only what a containment command means.
type ReachableSet func(ctx context.Context) (api.ReachableSet, error)

// commandPayload is the set_network_containment payload for a state and the reachable-address set in force. The change and the
// catch-up both build it here, so a host that is caught up gets exactly what the change queued. Marshalling cannot fail: every field
// is a number, a bool, or strings the store validated before writing them.
func commandPayload(state api.ContainmentState, reachable api.ReachableSet) []byte {
	payload, _ := json.Marshal(api.SetNetworkContainmentPayload{
		Version: state.Version, Epoch: state.Epoch, Contained: state.Contained,
		ReachableVersion: reachable.Version, Reachable: reachable.Addresses,
	})
	return payload
}

// carries reports whether a command's payload delivers state together with the reachable-address set at reachableVersion.
//
// A host's version and epoch identify one containment state, and the reachable version identifies one set, so those three are
// compared and nothing else. Including the reachable version is the whole of the convergence: a host already contained when the set
// changes has an unchanged containment state, so without it the host's latest command would still look current and the catch-up
// would never re-queue it, which is the "picks up a change without being released and contained again" the issue asks for.
func carries(cmd api.Command, state api.ContainmentState, reachableVersion int64) bool {
	var queued api.SetNetworkContainmentPayload
	return json.Unmarshal(cmd.Payload, &queued) == nil && queued.Version == state.Version && queued.Epoch == state.Epoch &&
		queued.ReachableVersion == reachableVersion
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
	reachable, err := s.reachable(ctx)
	if err != nil {
		return api.ContainmentState{}, err
	}
	if cmd, ok := latest[hostID]; ok {
		state.Delivery = deliveryOf(cmd, state, reachable.Version)
	}
	return state, nil
}

// deliveryOf describes a host's latest command. It is current when it carries both the state the host holds and the reachable set in
// force, so a host contained before the set last changed reads as still on its way rather than as settled.
func deliveryOf(cmd api.Command, state api.ContainmentState, reachableVersion int64) *api.ContainmentDelivery {
	return &api.ContainmentDelivery{
		CommandID: cmd.ID, Status: cmd.Status, Result: cmd.Result, Current: carries(cmd, state, reachableVersion),
	}
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
	reachable, err := s.reachable(ctx)
	if err != nil {
		return nil, err
	}
	for i := range states {
		if cmd, ok := latest[states[i].HostID]; ok {
			states[i].Delivery = deliveryOf(cmd, states[i], reachable.Version)
		}
	}
	return states, nil
}

// Set asks for a host to be contained or released. expected, when given, is the version the caller read before asking: the change is
// refused with api.ErrContainmentVersionConflict when the host has moved on since, so an operator acting on a stale view is told
// rather than applying over a change they never saw (issue #1076). Nil asks for the state whatever the host currently holds.
// A change is recorded, queued for the host and audited; a request for the state the
// host already has changes nothing. The state and its command are written in one transaction under the host's lock, so the commands
// queued for a host are in the order of the states they carry, and a change whose command cannot be queued records nothing and is
// refused rather than leaving a state for the catch-up to notice (issue #1073).
func (s *Service) Set(ctx context.Context, actor identityapi.PrincipalRef, remoteAddr, hostID string, contained bool,
	reason string, expected *int64) (api.ContainmentChange, error) {
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
	// Read BEFORE the change's transaction opens, so a slow read does not hold the host's row. A set read a moment before the
	// command is queued can be one version stale, and that is what the catch-up is for: the host reads as not current on the next
	// sweep and is re-queued. The direction that would matter is a host told it has allowances it does not, and that cannot happen
	// here, since the command carries the version of the set it was built from.
	reachable, err := s.reachable(ctx)
	if err != nil {
		return api.ContainmentChange{}, err
	}
	// The command is queued inside the transaction that records the state, so a change that cannot queue one records nothing: the
	// operator is told it failed rather than left with a state whose command the catch-up has to notice (issue #1073).
	state, changed, commandID, err := s.store.Set(ctx, hostID, contained, reason, actor.ID, expected,
		func(ctx context.Context, q sqlx.ExecerContext, state api.ContainmentState) (int64, error) {
			id, qerr := s.queue(ctx, q, hostID, api.CommandTypeSetNetworkContainment, commandPayload(state, reachable))
			if qerr != nil {
				return 0, qerr
			}
			// The audit entry commits with the change it records, so a host can never be found contained with nothing saying who
			// did it or why (issue #1070). Everything the row needs is known here, including the id of the command queued just
			// above, so the entry is written whole rather than held and completed later.
			entry, eerr := auditEntry(ctx, actor, remoteAddr, api.ContainmentChange{State: state, Changed: true, CommandID: id})
			if eerr != nil {
				return 0, eerr
			}
			if eerr := s.outbox.Enqueue(ctx, q, entry); eerr != nil {
				return 0, eerr
			}
			return id, nil
		})
	if err != nil {
		// A version conflict carries the state the refusal was decided against, which is what the caller needs to decide again;
		// every other failure carries nothing, because nothing about the host was established.
		if errors.Is(err, api.ErrContainmentVersionConflict) {
			return api.ContainmentChange{State: state}, err
		}
		return api.ContainmentChange{}, err
	}
	change := api.ContainmentChange{State: state, Changed: changed, CommandID: commandID}
	if !changed {
		return change, nil
	}
	// Both after the commit: a gateway told earlier could look for a command that is not there yet, and the entry is not a row to
	// deliver until the change it records is durable.
	s.notify(hostID)
	s.drain.DeliverSoon(ctx)
	return change, nil
}

// auditEntry encodes the change's audit event, ready to commit with it. An encoding failure fails the change rather than being
// logged past: the point of committing the entry with the change is that neither exists without the other.
func auditEntry(ctx context.Context, actor identityapi.PrincipalRef, remoteAddr string,
	change api.ContainmentChange) (auditoutbox.Entry, error) {
	action := identityapi.AuditHostRelease
	if change.State.Contained {
		action = identityapi.AuditHostContain
	}
	payload := map[string]any{"reason": change.State.Reason, "version": change.State.Version, "epoch": change.State.Epoch}
	if change.CommandID != 0 {
		payload["command_id"] = change.CommandID
	}
	return auditoutbox.Encode(identityapi.AuditEvent{
		Actor: actor, Action: action, TargetType: "host", TargetID: change.State.HostID, RemoteAddr: remoteAddr, Payload: payload,
		// Carried explicitly. The drain that delivers this entry may be another request's or the sweep's, and it detaches its own
		// trace so it cannot stamp one request's trace onto another's row, so an entry that does not carry its own arrives without.
		TraceID: identityapi.TraceIDFromContext(ctx),
	})
}
