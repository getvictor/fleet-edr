package reachable

import (
	"context"
	"slices"
	"strconv"
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

// diff reports what the replacement changed, as the strings an operator reads: destinations that arrived, destinations that left,
// and destinations that stayed but were renamed.
//
// Arrival and departure are judged on destination, port and transport, NOT on the whole entry: a note edited on an entry that
// already existed is not a destination arriving and leaving, and reporting it as both would bury whichever one actually changed. A
// rename is still a change worth recording, though, because the note is how the console and this trail name a destination, so it is
// reported as itself rather than dropped.
func diff(previous, next []api.ReachableAddress) (added, removed, renamed []string) {
	before := keyed(previous)
	after := keyed(next)
	for key, entry := range after {
		was, existed := before[key]
		switch {
		case !existed:
			added = append(added, label(entry))
		case was.Note != entry.Note:
			renamed = append(renamed, label(was)+" -> "+label(entry))
		}
	}
	for key, entry := range before {
		if _, ok := after[key]; !ok {
			removed = append(removed, label(entry))
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	slices.Sort(renamed)
	return added, removed, renamed
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

// label renders one entry the way an operator reads it: the destination, then the port and transport when it has them, then the name
// the operator gave it. The name is what makes the trail legible, since "the MDM server" is what a reviewer is looking for and an
// address is what they would otherwise have to recognise.
func label(a api.ReachableAddress) string {
	var b strings.Builder
	b.WriteString(a.CIDR)
	if a.Port != 0 {
		b.WriteString(":")
		b.WriteString(strconv.Itoa(a.Port))
	}
	if a.Transport != "" {
		b.WriteString("/")
		b.WriteString(a.Transport)
	}
	if a.Note != "" {
		b.WriteString(" (")
		b.WriteString(a.Note)
		b.WriteString(")")
	}
	return b.String()
}
