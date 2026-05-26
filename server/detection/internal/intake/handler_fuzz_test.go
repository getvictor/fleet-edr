package intake

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/fleetdm/edr/server/detection/api"
)

// FuzzParseAndValidateIngestBody drives the parse + per-event validation half of POST /api/events with random body bytes.
// The fuzz target asserts two invariants the spec contract makes on this surface:
//
//  1. Liveness: no input causes a panic, an unbounded allocation, or any other unrecoverable behavior. The harness wraps the
//     call in a defer/recover sanity net so a panic surfaces as a test failure with the offending input attached.
//  2. Contract: every (status, errCode) tuple is one of the documented set:
//     {(200, ""), (400, "invalid_json"), (400, "missing_fields_at_<i>"), (400, "host_id_mismatch")}.
//     Anything else (an undocumented status, a stray errCode, a 200 returned for a body that obviously isn't a well-formed
//     []api.Event) is a finding. The 413 body-cap and the 500 store-insert paths are upstream / downstream of this function
//     and are tested elsewhere; the fuzz keeps its blast radius to the parse + validate surface so the harness needs no DB.
//
// Why the pinnedHostID is a fixed sentinel: the production middleware threads the token-bound HostID through context; the
// fuzz only needs ONE host ID to exercise both the matching and the mismatching code paths (a fuzz-generated body's
// embedded host_id may or may not match this sentinel). Two distinct sentinels would double the search space without
// changing what's reachable.
//
// CLAUDE.md test-style decision matrix:
//
//	"Use Go's native go test -fuzz for untrusted input parsing including event JSON, policy diff, and agent HTTP bodies"
//
// This target closes the "event JSON" row.
func FuzzParseAndValidateIngestBody(f *testing.F) {
	seedCorpus(f)

	const pinnedHostID = "fuzz-pinned-host"
	f.Fuzz(func(t *testing.T, body []byte) {
		// Outer recover so a real panic surfaces as a clean test failure with the offending input attached. The fuzz engine
		// would catch the panic anyway, but the explicit %q'd input makes the failure log self-contained for reproducing.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseAndValidateIngestBody panicked on input %q: %v", body, r)
			}
		}()

		events, status, errCode := ParseAndValidateIngestBody(body, pinnedHostID)
		assertValidOutput(t, body, events, status, errCode, pinnedHostID)
	})
}

// assertValidOutput pins the (status, errCode) -> shape contract documented on ParseAndValidateIngestBody. Pulled out of the
// FuzzFunc body so the test failure message can include the exact tuple AND so a future contract addition (new error code) is a
// one-line edit here, not in the fuzz function.
//
// CodeRabbit #276 strengthening: the 200 oracle now re-validates the parsed events instead of only checking the body starts with
// `[`. A regression that 200'd on `[{}]` (which should be missing_fields_at_0) or a 200 with a host_id != pinnedHostID would
// have slipped through the previous oracle; the per-event field-population + host_id-match checks here pin the success contract
// against the validation logic, not just against the wire shape.
func assertValidOutput(t *testing.T, body []byte, events []api.Event, status int, errCode string, pinnedHostID string) {
	t.Helper()

	switch status {
	case http.StatusOK:
		if errCode != "" {
			t.Fatalf("status 200 returned with non-empty errCode %q for body %q", errCode, body)
		}
		// Sanity: a 200 result implies the body started with [ (a JSON array). An empty body or a non-array would not have
		// reached the loop. The body may have leading/trailing whitespace; trim before the prefix check.
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) > 0 && trimmed[0] != '[' {
			t.Fatalf("status 200 but body is not a JSON array: %q", body)
		}
		// Per-event field-population + host_id pin. The validation loop in ParseAndValidateIngestBody enforces these on every
		// event; a 200 that returns events failing either check would be a contract regression.
		for i, e := range events {
			if e.EventID == "" || e.HostID == "" || e.EventType == "" || e.TimestampNs == 0 {
				t.Fatalf("status 200 returned event[%d] with empty required field (event_id=%q host_id=%q event_type=%q timestamp_ns=%d) for body %q",
					i, e.EventID, e.HostID, e.EventType, e.TimestampNs, body)
			}
			if e.HostID != pinnedHostID {
				t.Fatalf("status 200 returned event[%d] with host_id %q != pinned %q for body %q",
					i, e.HostID, pinnedHostID, body)
			}
		}
		if len(events) > MaxIngestEventsPerRequest {
			t.Fatalf("status 200 returned %d events; exceeds MaxIngestEventsPerRequest=%d for body %q",
				len(events), MaxIngestEventsPerRequest, body)
		}
		// Trailing-bytes pin: a 200 implies the body parses cleanly as []api.Event with no trailing content. json.Unmarshal
		// rejects trailing bytes by contract (encoding/json package documentation), so using it as an independent oracle
		// catches the case where the streaming decoder accepts content past the closing `]`. Without this check, the
		// trailing-bytes seeds (`[]extra`, `[][]`, `[...]X`) silently pass because the events-slice contract on its own
		// doesn't see the trailing material.
		var reparsed []api.Event
		if err := json.Unmarshal(body, &reparsed); err != nil {
			t.Fatalf("status 200 but json.Unmarshal rejects the body: %v; body=%q", err, body)
		}

	case http.StatusBadRequest:
		// Any of the documented 400 error codes is acceptable. The fuzz pins the SET of codes; a stray code is a finding.
		switch {
		case errCode == "invalid_json":
			// Implies the JSON parse failed OR the body deserialized to nil (literal `null`, treated as a parse failure).
		case errCode == "host_id_mismatch":
			// Implies at least one event's host_id != pinnedHostID. We don't re-parse the body here to confirm — the parse
			// produced events, then a validation step caught the mismatch. Trusting the function's own report.
			_ = pinnedHostID
		case errCode == "too_many_events":
			// Implies the parsed array exceeded MaxIngestEventsPerRequest. Memory-amplification defense; the cap fires
			// before the per-event validation loop.
		case strings.HasPrefix(errCode, "missing_fields_at_"):
			// Implies an event at some index missed one of {event_id, host_id, event_type, timestamp_ns}.
		default:
			t.Fatalf("status 400 returned with undocumented errCode %q for body %q", errCode, body)
		}

	default:
		t.Fatalf("undocumented status %d (errCode %q) for body %q", status, errCode, body)
	}
}

// seedCorpus loads the curated entry set. Each entry exercises a distinct decision point in ParseAndValidateIngestBody;
// the fuzz engine extends from there via byte-flip / insert mutations.
func seedCorpus(f *testing.F) {
	f.Helper()
	// Happy path: an empty array (no events to validate; parses cleanly to []api.Event{} -> status 200).
	f.Add([]byte(`[]`))
	// One well-formed event matching the pinned host id. The TimestampNs must be non-zero per the validation rule.
	f.Add([]byte(`[{"event_id":"e1","host_id":"fuzz-pinned-host","event_type":"exec","timestamp_ns":1,"payload":{}}]`))
	// Two well-formed events, both pinned.
	f.Add([]byte(`[
        {"event_id":"e1","host_id":"fuzz-pinned-host","event_type":"exec","timestamp_ns":1,"payload":{}},
        {"event_id":"e2","host_id":"fuzz-pinned-host","event_type":"fork","timestamp_ns":2,"payload":{}}
    ]`))

	// invalid_json shapes.
	f.Add([]byte{})                         // empty body
	f.Add([]byte(`not json at all`))        // raw text
	f.Add([]byte(`[`))                      // unterminated array
	f.Add([]byte(`{"event_id":"e1"}`))      // object, not array
	f.Add([]byte(`[{`))                     // unterminated object inside array
	f.Add([]byte(`[null]`))                 // null instead of an event object
	f.Add([]byte(`[1,2,3]`))                // numbers instead of objects
	f.Add([]byte(`[{"event_id":1}]`))       // event_id wrong type (int instead of string) — json strict?
	f.Add([]byte(`[{"timestamp_ns":"x"}]`)) // timestamp_ns wrong type (string instead of int)

	// missing_fields shapes.
	f.Add([]byte(`[{}]`))                                                                                  // every required field missing
	f.Add([]byte(`[{"event_id":"e1"}]`))                                                                   // only event_id
	f.Add([]byte(`[{"event_id":"e1","host_id":"fuzz-pinned-host"}]`))                                      // missing event_type + timestamp_ns
	f.Add([]byte(`[{"event_id":"e1","host_id":"fuzz-pinned-host","event_type":"exec","timestamp_ns":0}]`)) // timestamp_ns zero is a miss

	// host_id_mismatch shapes.
	f.Add([]byte(`[{"event_id":"e1","host_id":"other-host","event_type":"exec","timestamp_ns":1,"payload":{}}]`))
	// First event matches pinned, second doesn't — exercises the loop's per-event check.
	f.Add([]byte(`[
        {"event_id":"e1","host_id":"fuzz-pinned-host","event_type":"exec","timestamp_ns":1,"payload":{}},
        {"event_id":"e2","host_id":"other-host","event_type":"exec","timestamp_ns":2,"payload":{}}
    ]`))

	// Adversarial / pathological shapes the fuzz engine might not synthesize on its own.
	f.Add(deepNestedArray(64))          // deeply-nested JSON arrays — JSON decoder stack
	f.Add(bytes.Repeat([]byte{0}, 256)) // a NULL-byte block
	// `["\xff"]` literal: the bytes on disk are the 8 ASCII characters [ " \ x f f " ]. Valid UTF-8 (no 0xFF byte ever
	// hits the parser); the JSON decoder rejects the input because `\xff` is not a recognized JSON escape sequence. This
	// seed exercises the escape-handling path, not the UTF-8-validity path.
	f.Add([]byte(`["\xff"]`))
	// Raw 0xFF byte inside the JSON string — actual invalid UTF-8 on the wire. The decoder's UTF-8 validity check
	// catches this one (distinct path from the escape-sequence rejection above).
	f.Add([]byte("[\"" + string([]byte{0xff}) + "\"]"))
	f.Add([]byte("[\"\x00\"]"))                     // U+0000 in a JSON string — historically a parser footgun
	f.Add([]byte("[{\"event_id\":\"e\x00nuls\"}]")) // NULs inside required-string field — exercise len()-vs-empty check
	// Long string field (~64 KiB event_id) to exercise large-value paths within the body cap.
	long := bytes.Repeat([]byte("a"), 64*1024)
	f.Add(fmt.Appendf(nil, `[{"event_id":%q,"host_id":"fuzz-pinned-host","event_type":"exec","timestamp_ns":1,"payload":{}}]`, long))
	// Mixed-validity ASCII + UTF-8 in a host_id (assert the comparator handles non-ASCII without crashing).
	if utf8.ValidString("ñöß-host") {
		f.Add([]byte(`[{"event_id":"e1","host_id":"ñöß-host","event_type":"exec","timestamp_ns":1,"payload":{}}]`))
	}

	// too_many_events seed (CodeRabbit #276): exercises the MaxIngestEventsPerRequest+1 rejection deterministically. Without
	// this seed the only path that hit the cap was a fuzz-mutator coincidence. Building the array as a bytes.Buffer keeps the
	// seed under a single allocation; ~10001 minimal events fit in well under 1 MiB on the wire.
	f.Add(tooManyEventsBody())

	// Trailing-bytes-after-`]` seeds. The streaming decoder (PR #276) rejects these via the `dec.Token() must return io.EOF`
	// check that runs after the closing `]`. json.Unmarshal previously rejected the same inputs, so the contract is preserved
	// across the shape change - these seeds make that preservation a TEST, not just an invariant in code review. A future
	// change that drops the trailing-EOF check (e.g., to enable `dec.UseNumber()`, `dec.DisallowUnknownFields()`, or any
	// other decoder mode that incidentally weakens the trailing-token assertion) would land here as a 200 instead of a 400,
	// and the assertValidOutput oracle would surface it as a contract regression.
	f.Add([]byte(`[]extra`))                                                                                   // trailing text after empty array
	f.Add([]byte(`[][]`))                                                                                      // two top-level JSON arrays back-to-back
	f.Add([]byte(`[{"event_id":"e","host_id":"fuzz-pinned-host","event_type":"exec","timestamp_ns":1}]X`))     // trailing byte after well-formed happy-path event
	f.Add([]byte(`[{"event_id":"e","host_id":"fuzz-pinned-host","event_type":"exec","timestamp_ns":1}] true`)) // trailing JSON literal after happy-path event
}

// tooManyEventsBody emits a JSON array of MaxIngestEventsPerRequest+1 minimal-but-valid events. Lives outside seedCorpus so
// f.Add takes one argument and the body construction stays linear. Every event matches the pinned host id so the rejection
// path is the cap (too_many_events), not the per-event validation that fires earlier in the loop.
func tooManyEventsBody() []byte {
	var b bytes.Buffer
	b.WriteByte('[')
	for i := range MaxIngestEventsPerRequest + 1 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"event_id":"e%d","host_id":"fuzz-pinned-host","event_type":"exec","timestamp_ns":1,"payload":{}}`, i)
	}
	b.WriteByte(']')
	return b.Bytes()
}

// deepNestedArray returns a JSON body that nests n levels of `[`s before closing with n `]`s. Probes the decoder's
// recursion depth handling without going so deep that the test itself OOMs.
func deepNestedArray(n int) []byte {
	var b bytes.Buffer
	for range n {
		b.WriteByte('[')
	}
	for range n {
		b.WriteByte(']')
	}
	return b.Bytes()
}
