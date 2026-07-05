// Package adminhttp holds the request helpers shared by the identity admin HTTP surfaces (useradmin, saadmin): parse the {id} path
// value, and decode a capped JSON body, each writing the identity admin error envelope ({"error": code}) on failure. Extracted so the
// two admin handlers share one copy instead of a byte-identical pair (consolidation pass). Each handler keeps its own route wiring and
// per-route body cap; only these two generic helpers are shared.
package adminhttp

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/fleetdm/edr/server/httpserver"
)

// PathID parses the {id} path value as a positive int64. On an absent, unparseable, or non-positive id it writes a 400
// {"error":"invalid_id"} and returns ok=false.
func PathID(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		httpserver.WriteJSONError(ctx, logger, w, http.StatusBadRequest, "invalid_id")
		return 0, false
	}
	return id, true
}

// DecodeBody reads the request body under limit and unmarshals it into dst, writing the matching identity admin error envelope and
// returning false when it has already written a response: "read_error" (read failure, 400), "body_too_large" (over the cap, 413), or
// "invalid_json" (a within-cap body that does not unmarshal, 400).
func DecodeBody(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	outcome := httpserver.DecodeCappedJSON(r, limit, dst)
	if outcome == httpserver.BodyReadFailed {
		httpserver.WriteJSONError(ctx, logger, w, http.StatusBadRequest, "read_error")
		return false
	}
	if outcome == httpserver.BodyTooLarge {
		httpserver.WriteJSONError(ctx, logger, w, http.StatusRequestEntityTooLarge, "body_too_large")
		return false
	}
	if outcome == httpserver.BodyInvalidJSON {
		httpserver.WriteJSONError(ctx, logger, w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}
