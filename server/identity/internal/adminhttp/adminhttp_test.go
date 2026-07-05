package adminhttp

import (
	"encoding/json"
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

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// errReader fails on the first Read, standing in for a client that hangs up mid-body.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body["error"]
}

func TestPathID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		id      string
		wantOK  bool
		wantVal int64
	}{
		{name: "valid", id: "42", wantOK: true, wantVal: 42},
		{name: "zero rejected", id: "0", wantOK: false},
		{name: "negative rejected", id: "-1", wantOK: false},
		{name: "unparseable rejected", id: "abc", wantOK: false},
		{name: "empty rejected", id: "", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.SetPathValue("id", tc.id)
			rec := httptest.NewRecorder()
			id, ok := PathID(t.Context(), discardLogger(), rec, req)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantVal, id)
				return
			}
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, "invalid_id", decodeError(t, rec))
		})
	}
}

func TestDecodeBody(t *testing.T) {
	t.Parallel()
	const limit = int64(16)
	type payload struct {
		Name string `json:"name"`
	}

	t.Run("valid body decodes", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(`{"name":"a"}`))
		rec := httptest.NewRecorder()
		var got payload
		assert.True(t, DecodeBody(t.Context(), discardLogger(), rec, req, limit, &got))
		assert.Equal(t, "a", got.Name)
	})

	t.Run("read error is 400 read_error", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", errReader{})
		rec := httptest.NewRecorder()
		var got payload
		assert.False(t, DecodeBody(t.Context(), discardLogger(), rec, req, limit, &got))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "read_error", decodeError(t, rec))
	})

	t.Run("over-cap body is 413 body_too_large", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(strings.Repeat("a", int(limit)+1)))
		rec := httptest.NewRecorder()
		var got payload
		assert.False(t, DecodeBody(t.Context(), discardLogger(), rec, req, limit, &got))
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		assert.Equal(t, "body_too_large", decodeError(t, rec))
	})

	t.Run("malformed JSON is 400 invalid_json", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(`{"name":`))
		rec := httptest.NewRecorder()
		var got payload
		assert.False(t, DecodeBody(t.Context(), discardLogger(), rec, req, limit, &got))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "invalid_json", decodeError(t, rec))
	})
}
