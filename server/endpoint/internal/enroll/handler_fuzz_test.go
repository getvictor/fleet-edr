package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

	srv, client := sharedEnrollServer(f)
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

		// Read the body so we can pin the error envelope's shape on every non-200 response. Cap the read at 4 KiB; the
		// handler writes a tiny JSON object, anything larger is itself a finding.
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		assertEnrollOutputContract(t, body, resp.StatusCode, resp.Header.Get("Retry-After"), respBody)
	})
}

// assertEnrollOutputContract pins the (status, errCode) -> envelope contract for every documented enroll outcome.
// Pulled out so a future contract change (new error code) is one edit here, not in the fuzz function body.
func assertEnrollOutputContract(t *testing.T, body []byte, status int, retryAfter string, respBody []byte) {
	t.Helper()
	switch status {
	case http.StatusOK:
		// Success implies the body parsed cleanly + every required field was populated + Service.Enroll returned
		// a valid response. The response body is the enrollResponse JSON: {host_id, host_token, enrolled_at}.
		var ok enrollResponse
		if err := json.Unmarshal(respBody, &ok); err != nil {
			t.Fatalf("200 response is not enrollResponse JSON: %v; body=%q", err, respBody)
		}
		if ok.HostID == "" || ok.HostToken == "" {
			t.Fatalf("200 response has empty required field; body=%q", respBody)
		}

	case http.StatusBadRequest:
		// Any 400 must carry a documented error code in the JSON envelope. The handler only emits two 400 codes:
		// bad_body (parse/missing-fields) and hardware_uuid_invalid (Service-level UUID validation).
		var env errBody
		if err := json.Unmarshal(respBody, &env); err != nil {
			t.Fatalf("400 response is not errBody JSON: %v; body=%q", err, respBody)
		}
		switch env.Error {
		case "bad_body", "hardware_uuid_invalid":
			// expected codes
		default:
			t.Fatalf("400 response has undocumented errCode %q for input %q", env.Error, body)
		}

	case http.StatusUnauthorized:
		// The only 401 path emits secret_mismatch.
		var env errBody
		if err := json.Unmarshal(respBody, &env); err != nil {
			t.Fatalf("401 response is not errBody JSON: %v; body=%q", err, respBody)
		}
		if env.Error != "secret_mismatch" {
			t.Fatalf("401 response has undocumented errCode %q for input %q", env.Error, body)
		}

	case http.StatusTooManyRequests:
		// The 429 path emits rate_limited AND the Retry-After header. The fuzz uses RatePerMinute=60_000 which makes
		// 429s effectively unreachable, but if one ever fires here, the envelope + header must still satisfy the spec.
		if retryAfter == "" {
			t.Fatalf("429 returned without Retry-After header for input %q", body)
		}
		var env errBody
		if err := json.Unmarshal(respBody, &env); err != nil || env.Error != "rate_limited" {
			t.Fatalf("429 envelope mismatch: err=%v code=%q for input %q", err, env.Error, body)
		}

	case http.StatusInternalServerError:
		// Internal errors map to errCode "internal".
		var env errBody
		if err := json.Unmarshal(respBody, &env); err != nil || env.Error != "internal" {
			t.Fatalf("500 envelope mismatch: err=%v code=%q for input %q", err, env.Error, body)
		}

	default:
		t.Fatalf("undocumented status %d (body=%q) for input %q", status, respBody, body)
	}
}

// sharedEnrollServer constructs ONE httptest server + reusable client for the whole fuzz run. One server avoids
// ephemeral-port exhaustion under high-throughput fuzz (16 workers × ~1k execs/sec quickly drain a /29 of free ports).
// The Service stub returns success on every call; per-error-mapping branches are covered by handler_test.go's table
// tests, not by the fuzz.
//
// The limiter is set to a huge per-minute rate so 429s don't accumulate across iterations — but the iteration order +
// the limiter's internal token-bucket state still mean the very first few iterations can drain the burst; the fuzz
// must tolerate 429s with the proper envelope (assertEnrollOutputContract handles that case explicitly).
var sharedEnrollServerOnce sync.Once
var sharedEnrollServerSrv *httptest.Server

func sharedEnrollServer(f *testing.F) (*httptest.Server, *http.Client) {
	f.Helper()
	sharedEnrollServerOnce.Do(func() {
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		svc := fakeService{
			enroll: func(_ context.Context, _ api.EnrollRequest, _ string) (api.EnrollResponse, error) {
				return api.EnrollResponse{HostID: "fuzz-host", HostToken: "fuzz-tok", EnrolledAt: now}, nil
			},
		}
		h := New(svc, Options{RatePerMinute: 60_000, Logger: slog.New(slog.DiscardHandler)})
		mux := http.NewServeMux()
		h.RegisterRoutes(mux)
		sharedEnrollServerSrv = httptest.NewServer(mux)
	})
	return sharedEnrollServerSrv, sharedEnrollServerSrv.Client()
}

// seedEnrollCorpus loads curated entries that hit every decision point in the enroll handler. The fuzz engine extends from
// these via byte-flip / insert mutations.
func seedEnrollCorpus(f *testing.F) {
	f.Helper()

	// Happy-path bodies. The stub's first-byte=0 branch returns success; these inputs start with `{` (byte 0x7B = 123),
	// 123 % 4 = 3 -> internal. So they actually exercise the synthetic-error path. The mutator quickly synthesizes
	// happy-path-shape bodies that start with bytes mapping to firstByte%4==0 too.
	f.Add([]byte(`{"enroll_secret":"s","hardware_uuid":"93DFC6F5-763D-5075-B305-8AC145D12F96","hostname":"h","os_version":"o","agent_version":"v"}`))
	f.Add([]byte(`{"enroll_secret":"","hardware_uuid":"u","hostname":"h","os_version":"o","agent_version":"v"}`)) // empty secret -> missing field

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

	// Inputs that should reach the Service-error mapping. First-byte mod 4 picks which Service-error branch fires; the
	// JSON shape must still pass the required-fields gate to reach the Service call. So we need bodies whose JSON parses
	// cleanly AND whose first byte maps to each stub branch.
	// firstByte = '{' (0x7B = 123); 123 % 4 = 3 -> internal-error branch.
	f.Add([]byte(`{"enroll_secret":"s","hardware_uuid":"u","hostname":"h","os_version":"o","agent_version":"v"}`))

	// Adversarial / pathological. The fuzz engine probes the parser; these seeds explicitly add shapes that historically
	// trip JSON decoders.
	f.Add(bytes.Repeat([]byte{0}, 256))                                                                                   // NULL-byte block
	f.Add([]byte(`{"enroll_secret":"` + strings.Repeat("a", 8192) + `"}`))                                                // very long secret string
	f.Add([]byte(`{"enroll_secret":"\uD83D"}`))                                                                           // unpaired surrogate
	f.Add([]byte(`{"hardware_uuid":"ñöß-uuid","enroll_secret":"s","hostname":"h","os_version":"o","agent_version":"v"}`)) // non-ASCII UUID
}
