package reachable

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/fleetdm/edr/server/auditoutbox"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
)

// Service reads and replaces the reachable-address set.
type Service struct {
	store *Store
	drain *auditoutbox.Drain
}

// NewService builds a Service. store is required; drain may be nil outside production, which leaves a replacement's audit entry in
// the outbox rather than turning it into an audit row.
func NewService(store *Store, drain *auditoutbox.Drain) *Service {
	if store == nil {
		panic("reachable.NewService: store is required")
	}
	return &Service{store: store, drain: drain}
}

// Get returns the stored set.
func (s *Service) Get(ctx context.Context) (api.ReachableSet, error) {
	return s.store.Get(ctx)
}

// Replace validates addresses and stores them as the new set.
//
// The reason is required and is recorded with the change, like a containment's: this is the one edit that weakens a containment
// already in force, and the question an incident review asks is who widened it and why, which the set's own row cannot answer.
//
// expected makes the replacement conditional on the version the caller read, so two operators editing the set at once are told
// rather than one silently overwriting the other.
func (s *Service) Replace(ctx context.Context, actor identityapi.PrincipalRef, remoteAddr string,
	addresses []api.ReachableAddress, reason string, expected *int64) (api.ReachableSet, error) {
	switch {
	case utf8.RuneCountInString(reason) > api.MaxReachableReasonLength:
		return api.ReachableSet{}, api.ErrReachableReasonTooLong
	case strings.TrimSpace(reason) == "":
		return api.ReachableSet{}, api.ErrReachableReasonRequired
	}
	reason = strings.TrimSpace(reason)
	normalized, err := Normalize(addresses)
	if err != nil {
		return api.ReachableSet{}, err
	}
	_, next, err := s.store.Replace(ctx, normalized, actor.ID, expected,
		func(previous, next api.ReachableSet) (auditoutbox.Entry, error) {
			return auditEntry(ctx, actor, remoteAddr, reason, previous, next)
		})
	if err != nil {
		return api.ReachableSet{}, err
	}
	s.drain.DeliverSoon(ctx)
	return next, nil
}

// auditEntry encodes the replacement's audit event, ready to commit with it. An encoding failure fails the change rather than being
// logged past: the point of committing the entry with the change is that neither exists without the other.
//
// The payload carries what changed rather than only the new set, because that is what a reviewer is reading for. A set of twenty
// addresses that gained one is indistinguishable from the same set re-saved unless the entry says which one arrived.
func auditEntry(ctx context.Context, actor identityapi.PrincipalRef, remoteAddr, reason string,
	previous, next api.ReachableSet) (auditoutbox.Entry, error) {
	added, removed, renamed := diff(previous.Addresses, next.Addresses)
	payload := map[string]any{
		"reason":  reason,
		"version": next.Version,
		"count":   len(next.Addresses),
	}
	if len(added) > 0 {
		payload["added"] = added
	}
	if len(removed) > 0 {
		payload["removed"] = removed
	}
	if len(renamed) > 0 {
		payload["renamed"] = renamed
	}
	return auditoutbox.Encode(identityapi.AuditEvent{
		Actor: actor, Action: identityapi.AuditContainmentReachableUpdate, TargetType: "containment_config",
		TargetID: "reachable_addresses", RemoteAddr: remoteAddr, Payload: payload,
		// Carried explicitly: the drain that delivers this entry may be another request's or the sweep's, and it detaches its own
		// trace, so an entry that does not carry its own arrives without one.
		TraceID: identityapi.TraceIDFromContext(ctx),
	})
}

// diff reports what the replacement changed, as the entries themselves: destinations that arrived, destinations that left, and
// destinations that stayed but were renamed.
//
// Structured, NOT rendered. An earlier version joined the fields into strings like "10.0.0.0/8 (corporate)" and paired renames with
// an arrow, which put an operator-controlled note inside a format a reader has to parse: a note containing the delimiter, a bracket
// or a newline could make one change read as another in the trail that exists to record who widened containment. Entries carry their
// own fields instead, so there is no delimiter to forge and a reader can filter on a field rather than pattern-match a sentence.
//
// Arrival and departure are judged on destination, port and transport, NOT on the whole entry: a note edited on an entry that
// already existed is not a destination arriving and leaving, and reporting it as both would bury whichever one actually changed. A
// rename is still a change worth recording, though, because the note is how the console and this trail name a destination.
func diff(previous, next []api.ReachableAddress) (added, removed []api.ReachableAddress, renamed []map[string]api.ReachableAddress) {
	before := keyed(previous)
	after := keyed(next)
	for key, entry := range after {
		was, existed := before[key]
		switch {
		case !existed:
			added = append(added, entry)
		case was.Note != entry.Note:
			renamed = append(renamed, map[string]api.ReachableAddress{"from": was, "to": entry})
		}
	}
	for key, entry := range before {
		if _, ok := after[key]; !ok {
			removed = append(removed, entry)
		}
	}
	// Sorted so one replacement always renders the same way, whatever order the map walked in.
	slices.SortFunc(added, byDestination)
	slices.SortFunc(removed, byDestination)
	slices.SortFunc(renamed, func(a, b map[string]api.ReachableAddress) int { return byDestination(a["to"], b["to"]) })
	return added, removed, renamed
}

// byDestination orders entries the way an operator reads them, by address then port then transport.
func byDestination(a, b api.ReachableAddress) int {
	return cmp.Or(strings.Compare(a.CIDR, b.CIDR), cmp.Compare(a.Port, b.Port), strings.Compare(a.Transport, b.Transport))
}

// keyed indexes entries by destination alone, so the same destination under two notes is one key.
func keyed(addresses []api.ReachableAddress) map[api.ReachableAddress]api.ReachableAddress {
	out := make(map[api.ReachableAddress]api.ReachableAddress, len(addresses))
	for _, a := range addresses {
		key := a
		key.Note = ""
		out[key] = a
	}
	return out
}
