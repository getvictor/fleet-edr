package mysql

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/fleetdm/edr/server/detection/api"
)

// searchCursor is the keyset position for the fleet-wide process search (issue #582): the (fork_time_ns, id) of the last row of the
// previous page. The compound key is required because fork_time_ns is not unique (a batched fork burst shares one instant), so id
// breaks ties and gives a total order; paging on this pair is stable when new rows arrive at the head between requests.
type searchCursor struct {
	forkTimeNs int64
	id         int64
}

// encodeCursor renders a cursor as an opaque base64url token. Opaque so callers treat pagination as a server-owned contract rather
// than depending on the "<fork>:<id>" shape; it is still trivially decodable server-side.
func encodeCursor(c searchCursor) string {
	raw := strconv.FormatInt(c.forkTimeNs, 10) + ":" + strconv.FormatInt(c.id, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeCursor parses a token produced by encodeCursor. A token that does not decode is a caller error (the handler maps it to 400),
// never a silent full scan.
func decodeCursor(token string) (searchCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return searchCursor{}, fmt.Errorf("%w: not base64url: %w", api.ErrInvalidCursor, err)
	}
	fork, id, ok := strings.Cut(string(raw), ":")
	if !ok {
		return searchCursor{}, fmt.Errorf("%w: missing fork:id separator", api.ErrInvalidCursor)
	}
	forkNs, err := strconv.ParseInt(fork, 10, 64)
	if err != nil {
		return searchCursor{}, fmt.Errorf("%w: fork_time_ns: %w", api.ErrInvalidCursor, err)
	}
	rowID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return searchCursor{}, fmt.Errorf("%w: id: %w", api.ErrInvalidCursor, err)
	}
	return searchCursor{forkTimeNs: forkNs, id: rowID}, nil
}
