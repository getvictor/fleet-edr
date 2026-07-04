package api

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// The artifact field each searchable event type matches on: a network connection's remote address, a DNS query's query name. Shared
// by every EventArchive implementation so a new event type is added in one place and the ClickHouse store and the in-memory fake
// cannot drift (the ClickHouse column and the JSON payload field happen to share these names).
const (
	fieldRemoteAddress = "remote_address"
	fieldQueryName     = "query_name"
)

// TimelineEventTypes is the ordered allowlist of event classes the host event timeline surfaces (issue #583): a process starting a
// new image, an outbound/inbound connection, and a DNS resolution. fork/exit lineage is the graph's job, not the flat stream. Shared
// by the ClickHouse store, the fake, and the handler so the allowlist lives in one place.
func TimelineEventTypes() []string { return []string{"exec", "network_connect", "dns_query"} }

// IsTimelineEventType reports whether eventType is one the timeline surfaces. The handler uses it to reject an unrecognized ?type=.
func IsTimelineEventType(eventType string) bool {
	switch eventType {
	case "exec", "network_connect", "dns_query":
		return true
	default:
		return false
	}
}

// EffectiveTimelineEventTypes resolves the event classes a HostTimeline query matches: all timeline classes when requested is empty,
// otherwise the deduplicated intersection of requested with the allowlist. This makes the archive layer's contract (timeline classes
// only) enforceable independently of any caller-side validation, and bounds the set to the allowlist size regardless of a pathological
// requested slice (e.g. type=exec,exec,exec,...). An empty return means the caller requested only non-timeline classes, so the query
// matches nothing. Shared by the ClickHouse store and the fake so they cannot diverge on which classes a filter admits.
func EffectiveTimelineEventTypes(requested []string) []string {
	if len(requested) == 0 {
		return TimelineEventTypes()
	}
	seen := make(map[string]bool, len(requested))
	var out []string
	for _, t := range requested {
		if IsTimelineEventType(t) && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// ArtifactField returns the payload/column field a fleet-wide search of eventType matches against, and ok=false for a type that has
// no artifact search. Callers (the ClickHouse store, the in-memory fake, the handler) share this one mapping.
func ArtifactField(eventType string) (string, bool) {
	// Event-type strings match schema/events.json; the codebase carries them as literals rather than a shared enum.
	switch eventType {
	case "network_connect":
		return fieldRemoteAddress, true
	case "dns_query":
		return fieldQueryName, true
	default:
		return "", false
	}
}

// EventCursor is the keyset position for the fleet-wide event search (issue #582): the (timestamp_ns, event_id) of the last event of
// the previous page. timestamp_ns is not unique, so event_id (the archive's own final sort-key column) breaks ties for a total order.
type EventCursor struct {
	TimestampNs int64
	EventID     string
}

// EncodeEventCursor renders a cursor as an opaque base64url token. The raw form is "<timestamp_ns>:<event_id>"; timestamp_ns is
// purely numeric so the first ':' delimits it and the remainder is the event_id verbatim (an event_id may itself contain ':'). Shared
// by the real store and the fake so both speak one wire token.
func EncodeEventCursor(c EventCursor) string {
	raw := strconv.FormatInt(c.TimestampNs, 10) + ":" + c.EventID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeEventCursor parses a token produced by EncodeEventCursor, wrapping ErrInvalidEventCursor on any malformed token so the handler
// maps it to 400 rather than scanning.
func DecodeEventCursor(token string) (EventCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return EventCursor{}, fmt.Errorf("%w: not base64url: %w", ErrInvalidEventCursor, err)
	}
	ts, id, ok := strings.Cut(string(raw), ":")
	if !ok {
		return EventCursor{}, fmt.Errorf("%w: missing ts:event_id separator", ErrInvalidEventCursor)
	}
	tsNs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return EventCursor{}, fmt.Errorf("%w: timestamp_ns: %w", ErrInvalidEventCursor, err)
	}
	return EventCursor{TimestampNs: tsNs, EventID: id}, nil
}
