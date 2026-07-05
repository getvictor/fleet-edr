package httpserver

import (
	"encoding/json"
	"io"
	"net/http"
)

// BodyOutcome classifies the result of ReadCappedBody / DecodeCappedJSON so each caller maps it to its own context's typed error
// code and HTTP status. The helpers deliberately write no response: the operator and identity admin surfaces have distinct
// error-code vocabularies (`detection_config.invalid_json`, a bare `invalid_json`, and so on), so response shaping stays at the call
// site while the read-and-size invariant lives here.
type BodyOutcome int

const (
	// BodyOK means the body was read (and, for DecodeCappedJSON, unmarshalled) within the cap.
	BodyOK BodyOutcome = iota
	// BodyReadFailed means reading r.Body itself failed (a client hangup, for example). Callers map it to 400.
	BodyReadFailed
	// BodyTooLarge means the body exceeded the cap. Callers map it to 413.
	BodyTooLarge
	// BodyInvalidJSON means a within-cap body did not unmarshal. Only DecodeCappedJSON returns it. Callers map it to 400.
	BodyInvalidJSON
)

// ReadCappedBody reads r.Body under a byte cap and returns the bytes with a BodyOutcome the caller maps to a typed response. It
// reads limit+1 bytes so a body larger than the cap is reported as BodyTooLarge rather than silently truncated to a parseable
// prefix (a truncated payload would otherwise surface as a misleading invalid-JSON 400 or, worse, a partial-but-valid mutation).
// Centralizing the read+size check keeps the several mutation handlers that enforce it from drifting (reading limit instead of
// limit+1, or comparing with the wrong operator). It never returns BodyInvalidJSON.
func ReadCappedBody(r *http.Request, limit int64) ([]byte, BodyOutcome) {
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, BodyReadFailed
	}
	if int64(len(body)) > limit {
		return nil, BodyTooLarge
	}
	return body, BodyOK
}

// DecodeCappedJSON reads r.Body under a byte cap (see ReadCappedBody) and unmarshals it into dst, which must be a non-nil pointer.
// It returns BodyInvalidJSON when a within-cap body does not unmarshal, and otherwise the same outcomes as ReadCappedBody. Like
// ReadCappedBody it writes no response; the caller maps the outcome to its typed error code.
func DecodeCappedJSON(r *http.Request, limit int64, dst any) BodyOutcome {
	body, outcome := ReadCappedBody(r, limit)
	if outcome != BodyOK {
		return outcome
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return BodyInvalidJSON
	}
	return BodyOK
}
