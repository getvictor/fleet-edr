package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fleetdm/edr/server/endpoint/api"
)

// FuzzEnrollBody drives the full POST /api/enroll handler with random body bytes. Parallel to FuzzParseAndValidateIngestBody
// in server/detection/internal/intake/: same untrusted-public-input boundary, same shape, same liveness + contract
// invariants. /api/enroll is unauthenticated (rate-limited per source IP); the body must survive every fuzzer-synthesized
// shape without panicking, and every (status, errCode) tuple must be one of the documented set.
//
// Documented set on the enroll handler (per server/endpoint/internal/enroll/handler.go):
//
//	(200, "")                    success — Service.Enroll returned a token
//	(400, "bad_body")            body parse failure OR missing required field
//	(400, "hardware_uuid_invalid") Service returned api.ErrInvalidHardwareUUID
//	(401, "secret_mismatch")     Service returned api.ErrInvalidSecret
//	(429, "rate_limited")        per-IP rate limit (with Retry-After header)
//	(500, "internal")            Service returned any other error
//
// The fuzz drives the full handler (not a refactored parse helper) because /api/enroll's body cap is integrated with the
// per-IP rate limiter and the Service-injection seam: the handler wraps r.Body in MaxBytesReader and decodes via
// json.NewDecoder, so the cap-vs-parse interaction matters. The fakeService stub avoids a real DB.
//
// Service stub strategy: the stub returns success on every call. The fuzz's job is to verify the parse + body-cap +
// required-fields path; the Service-error mapping branches (secret_mismatch, hardware_uuid_invalid, internal) are
// table-tested in handler_test.go. Folding the error-mapping into the fuzz would require per-request port allocation
// (one server per stub behavior), which exhausts ephemeral ports during a high-throughput fuzz. One shared server is the
// trade-off that lets the fuzz hit 1k+ execs/sec without TCP-port-pool starvation.
//
// CLAUDE.md test-style decision matrix:
//
//	"Use Go's native go test -fuzz for untrusted input parsing including event JSON, policy diff, and agent HTTP bodies"
//
// This closes the "agent HTTP bodies" row for the enroll surface — the other public agent body path.
func FuzzEnrollBody(f *testing.F) {
	seedEnrollCorpus(f)

	srv := sharedEnrollServer()
	client := srv.Client()
	url := srv.URL + "/api/enroll"

	f.Fuzz(func(t *testing.T, body []byte) {
		// Outer recover so a panic surfaces with the offending input attached. The fuzz engine catches panics anyway; the
		// explicit %q'd input makes the failure log self-contained for reproduction.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("enroll handler panicked on input %q: %v", body, r)
			}
		}()

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("send request: %v", err)
		}
		defer resp.Body.Close()

		// Read the body so we can pin the error envelope's shape on every non-200 response. Cap the read at maxRespBody;
		// the handler writes a tiny JSON object, anything larger is itself a finding. io.LimitReader returns EOF rather
		// than a distinct "limit exceeded" error (see golang/go#51115), so a body that's >maxRespBody bytes would
		// silently truncate and any prefix that happens to parse would be accepted. The +1 read + len check catches the
		// oversize case explicitly (CodeRabbit #276).
		const maxRespBody = 4096
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBody+1))
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		if len(respBody) > maxRespBody {
			t.Fatalf("response body exceeded %d bytes for input %q", maxRespBody, body)
		}

		assertEnrollOutputContract(t, body, resp.StatusCode, resp.Header.Get("Retry-After"), respBody)
	})
}

// assertEnrollOutputContract pins the (status, errCode) -> envelope contract for every documented enroll outcome. The switch dispatches to per-status helpers; the helpers do the JSON parse + error-code check so this function stays linear (cognitive complexity ≤ 15 per Sonar S3776).
func assertEnrollOutputContract(t *testing.T, body []byte, status int, retryAfter string, respBody []byte) {
	t.Helper()
	switch status {
	case http.StatusOK:
		assertEnroll200(t, respBody)
	case http.StatusBadRequest:
		assertEnrollErrBody(t, body, respBody, http.StatusBadRequest, "bad_body", "hardware_uuid_invalid")
	case http.StatusUnauthorized:
		assertEnrollErrBody(t, body, respBody, http.StatusUnauthorized, "secret_mismatch")
	case http.StatusTooManyRequests:
		if retryAfter == "" {
			t.Fatalf("429 returned without Retry-After header for input %q", body)
		}
		assertEnrollErrBody(t, body, respBody, http.StatusTooManyRequests, "rate_limited")
	case http.StatusInternalServerError:
		assertEnrollErrBody(t, body, respBody, http.StatusInternalServerError, "internal")
	default:
		t.Fatalf("undocumented status %d (body=%q) for input %q", status, respBody, body)
	}
}

// assertEnroll200 pins the success-response shape. Success implies the body parsed cleanly + every required field was populated +
// Service.Enroll returned a valid response. The response body is the enrollResponse JSON: {host_id, host_token, enrolled_at}.
// All three fields are required; the EnrolledAt check (CodeRabbit #276) closes the gap where a regression that dropped
// enrolled_at from the response wire shape would have slipped through.
func assertEnroll200(t *testing.T, respBody []byte) {
	t.Helper()
	var ok enrollResponse
	if err := json.Unmarshal(respBody, &ok); err != nil {
		t.Fatalf("200 response is not enrollResponse JSON: %v; body=%q", err, respBody)
	}
	if ok.HostID == "" || ok.HostToken == "" {
		t.Fatalf("200 response has empty required field; body=%q", respBody)
	}
	if ok.EnrolledAt.IsZero() {
		t.Fatalf("200 response missing enrolled_at; body=%q", respBody)
	}
}

// assertEnrollErrBody pins the error-envelope contract: every non-200 response is `{"error": "<code>"}` JSON and the code is in the allow-list the caller passed. allowed is variadic so each status' set of codes is documented at the call site.
func assertEnrollErrBody(t *testing.T, body, respBody []byte, status int, allowed ...string) {
	t.Helper()
	var env errBody
	if err := json.Unmarshal(respBody, &env); err != nil {
		t.Fatalf("%d response is not errBody JSON: %v; body=%q", status, err, respBody)
	}
	if slices.Contains(allowed, env.Error) {
		return
	}
	t.Fatalf("%d response has undocumented errCode %q (allowed=%v) for input %q", status, env.Error, allowed, body)
}

// sharedEnrollServer constructs ONE httptest server + reusable client for the whole fuzz run. One server avoids
// ephemeral-port exhaustion under high-throughput fuzz (16 workers × ~1k execs/sec quickly drain a /29 of free ports).
// The Service stub returns success on every call; per-error-mapping branches are covered by handler_test.go's table
// tests, not by the fuzz.
//
// The limiter is set to a huge per-minute rate so 429s don't accumulate across iterations — but the iteration order +
// the limiter's internal token-bucket state still mean the very first few iterations can drain the burst; the fuzz
// must tolerate 429s with the proper envelope (assertEnrollOutputContract handles that case explicitly).
//
// sync.OnceValue (Go 1.21+) gives a non-nilable return without the global-variable indirection that the older
// sync.Once+global pattern needs. nilaway can prove the returned *httptest.Server is non-nil because newSharedEnrollServer
// always constructs and returns a value, whereas the older pattern hid the assignment inside a closure that nilaway's
// dataflow couldn't follow.
var sharedEnrollServer = sync.OnceValue(newSharedEnrollServer)

func newSharedEnrollServer() *httptest.Server {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := fakeService{
		enroll: func(_ context.Context, _ api.EnrollRequest, _ string) (api.EnrollResponse, error) {
			return api.EnrollResponse{HostID: "fuzz-host", HostToken: "fuzz-tok", EnrolledAt: now}, nil
		},
	}
	h := New(svc, Options{RatePerMinute: 60_000, Logger: slog.New(slog.DiscardHandler)})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return httptest.NewServer(mux)
}

// seedEnrollCorpus loads curated entries that hit every decision point in the enroll handler. The fuzz engine extends
// from these via byte-flip / insert mutations.
func seedEnrollCorpus(f *testing.F) {
	f.Helper()

	// Happy-path-shape bodies. All required fields populated; the stub returns success.
	f.Add([]byte(`{"enroll_secret":"s","hardware_uuid":"93DFC6F5-763D-5075-B305-8AC145D12F96","hostname":"h","os_version":"o","agent_version":"v"}`))
	// Empty secret — all-fields-required gate rejects with bad_body before Service.Enroll is called.
	f.Add([]byte(`{"enroll_secret":"","hardware_uuid":"u","hostname":"h","os_version":"o","agent_version":"v"}`))

	// bad_body shapes.
	f.Add([]byte{})                                        // empty body
	f.Add([]byte(`not json`))                              // raw text
	f.Add([]byte(`{`))                                     // unterminated object
	f.Add([]byte(`{"enroll_secret":"s"}`))                 // missing other required fields
	f.Add([]byte(`null`))                                  // top-level null
	f.Add([]byte(`[]`))                                    // top-level array (struct decoder rejects)
	f.Add([]byte(`{"enroll_secret":1}`))                   // wrong type for string field
	f.Add([]byte(strings.Repeat("{", 100)))                // deeply truncated JSON
	f.Add(bytes.Repeat([]byte("a"), maxEnrollBodyBytes+1)) // over the body cap; cap-trip path

	// A second happy-path-shape body for the mutator to anchor mutations on. With the always-success stub this exercises
	// the same Service.Enroll → 200 path as the first happy-path seed; redundant on the seed list but a useful anchor for
	// the mutator's byte-flip generations.
	f.Add([]byte(`{"enroll_secret":"s","hardware_uuid":"u","hostname":"h","os_version":"o","agent_version":"v"}`))

	// Adversarial / pathological. The fuzz engine probes the parser; these seeds explicitly add shapes that historically
	// trip JSON decoders.
	f.Add(bytes.Repeat([]byte{0}, 256))                                                                                   // NULL-byte block
	f.Add([]byte(`{"enroll_secret":"` + strings.Repeat("a", 8192) + `"}`))                                                // very long secret string
	f.Add([]byte(`{"enroll_secret":"\uD83D"}`))                                                                           // unpaired surrogate
	f.Add([]byte(`{"hardware_uuid":"ñöß-uuid","enroll_secret":"s","hostname":"h","os_version":"o","agent_version":"v"}`)) // non-ASCII UUID
}
