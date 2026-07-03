package clickhouse

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/fleetdm/edr/server/visibility/api"
)

// eventCursor is the keyset position for the fleet-wide event search (issue #582): the (timestamp_ns, event_id) of the last event of
// the previous page. timestamp_ns is not unique, so event_id (the archive's own final sort-key column) breaks ties for a total order.
type eventCursor struct {
	timestampNs int64
	eventID     string
}

// encodeEventCursor renders a cursor as an opaque base64url token. The raw form is "<timestamp_ns>:<event_id>"; timestamp_ns is
// purely numeric so the first ':' delimits it and the remainder is the event_id verbatim (an event_id may itself contain ':').
func encodeEventCursor(c eventCursor) string {
	raw := strconv.FormatInt(c.timestampNs, 10) + ":" + c.eventID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeEventCursor parses a token produced by encodeEventCursor. A token that does not decode wraps api.ErrInvalidEventCursor so the
// handler maps it to 400 rather than silently scanning.
func decodeEventCursor(token string) (eventCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return eventCursor{}, fmt.Errorf("%w: not base64url: %w", api.ErrInvalidEventCursor, err)
	}
	ts, id, ok := strings.Cut(string(raw), ":")
	if !ok {
		return eventCursor{}, fmt.Errorf("%w: missing ts:event_id separator", api.ErrInvalidEventCursor)
	}
	tsNs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return eventCursor{}, fmt.Errorf("%w: timestamp_ns: %w", api.ErrInvalidEventCursor, err)
	}
	return eventCursor{timestampNs: tsNs, eventID: id}, nil
}
