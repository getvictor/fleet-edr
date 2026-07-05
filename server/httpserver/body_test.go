package httpserver

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errReader fails on the first Read, standing in for a client that hangs up mid-body.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestReadCappedBody(t *testing.T) {
	t.Parallel()

	const limit = int64(16)
	cases := []struct {
		name    string
		body    string
		want    BodyOutcome
		wantLen int
	}{
		{name: "empty body is OK", body: "", want: BodyOK, wantLen: 0},
		{name: "under the cap is OK", body: strings.Repeat("a", int(limit)-1), want: BodyOK, wantLen: int(limit) - 1},
		{name: "exactly at the cap is OK", body: strings.Repeat("a", int(limit)), want: BodyOK, wantLen: int(limit)},
		{name: "one byte over the cap is TooLarge", body: strings.Repeat("a", int(limit)+1), want: BodyTooLarge},
		{name: "far over the cap is TooLarge", body: strings.Repeat("a", int(limit)*10), want: BodyTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(t.Context(), "POST", "/", strings.NewReader(tc.body))
			body, outcome := ReadCappedBody(req, limit)
			assert.Equal(t, tc.want, outcome)
			if tc.want == BodyOK {
				assert.Len(t, body, tc.wantLen)
			} else {
				assert.Nil(t, body, "no bytes are returned on a non-OK outcome")
			}
		})
	}

	t.Run("a read error is BodyReadFailed", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/", errReader{})
		body, outcome := ReadCappedBody(req, limit)
		assert.Equal(t, BodyReadFailed, outcome)
		assert.Nil(t, body)
	})

	t.Run("a body at the cap is never truncated", func(t *testing.T) {
		t.Parallel()
		// Regression guard for the limit+1 invariant: a body exactly at the cap must come back whole, not clipped.
		want := strings.Repeat("x", int(limit))
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/", strings.NewReader(want))
		body, outcome := ReadCappedBody(req, limit)
		require.Equal(t, BodyOK, outcome)
		assert.Equal(t, want, string(body))
	})
}

func TestDecodeCappedJSON(t *testing.T) {
	t.Parallel()

	const limit = int64(64)
	type payload struct {
		Name string `json:"name"`
	}

	t.Run("valid JSON within the cap unmarshals", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/", strings.NewReader(`{"name":"edr"}`))
		var got payload
		outcome := DecodeCappedJSON(req, limit, &got)
		assert.Equal(t, BodyOK, outcome)
		assert.Equal(t, "edr", got.Name)
	})

	t.Run("malformed JSON within the cap is BodyInvalidJSON", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/", strings.NewReader(`{"name":`))
		var got payload
		outcome := DecodeCappedJSON(req, limit, &got)
		assert.Equal(t, BodyInvalidJSON, outcome)
	})

	t.Run("over-cap body is TooLarge before the unmarshal is attempted", func(t *testing.T) {
		t.Parallel()
		// Valid JSON, but past the cap: the size check must win so a huge-but-parseable body cannot slip through.
		big := `{"name":"` + strings.Repeat("a", int(limit)) + `"}`
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/", strings.NewReader(big))
		var got payload
		outcome := DecodeCappedJSON(req, limit, &got)
		assert.Equal(t, BodyTooLarge, outcome)
		assert.Empty(t, got.Name, "dst is left untouched when the body is rejected")
	})

	t.Run("a read error is BodyReadFailed", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/", errReader{})
		var got payload
		outcome := DecodeCappedJSON(req, limit, &got)
		assert.Equal(t, BodyReadFailed, outcome)
	})

	// Guard the documented contract that DecodeCappedJSON layers on ReadCappedBody: an over-cap body is never a decode attempt.
	require.NotPanics(t, func() {
		req := httptest.NewRequestWithContext(t.Context(), "POST", "/", io.LimitReader(strings.NewReader(strings.Repeat("a", 200)), 200))
		var got payload
		_ = DecodeCappedJSON(req, limit, &got)
	})
}

func TestWriteJSONError(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	WriteJSONError(t.Context(), logger, rec, http.StatusBadRequest, "invalid_json")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.JSONEq(t, `{"error":"invalid_json"}`, rec.Body.String())
}
