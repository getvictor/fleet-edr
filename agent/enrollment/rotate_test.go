package enrollment

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rotateTestServer stands up a minimal /api/enroll responder so the
// initial enroll succeeds; Rotate is a pure-local op so rotateTestServer
// is only consulted on the very first Ensure.
func rotateTestServer(t *testing.T, hostID string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"host_id":"` + hostID + `","host_token":"original-token","enrolled_at":"2026-05-03T18:00:00Z"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestProvider(t *testing.T) (TokenProvider, string) {
	t.Helper()
	srv := rotateTestServer(t, "host-1")
	tokenFile := filepath.Join(t.TempDir(), "enrolled.plist")
	tp, err := Ensure(t.Context(), Options{
		ServerURL:      srv.URL,
		EnrollSecret:   "s",
		TokenFile:      tokenFile,
		AllowInsecure:  true,
		HostIDOverride: "host-1",
	})
	require.NoError(t, err)
	require.Equal(t, "original-token", tp.Token())
	return tp, tokenFile
}

// Happy path: Rotate replaces the in-memory + on-disk token, the next
// Token() returns the new value, and the on-disk plist parses back to
// the same shape (so a subsequent agent restart loads the rotated
// token rather than the original).
func TestRotate_HappyPath(t *testing.T) {
	tp, tokenFile := newTestProvider(t)
	const newTok = "rotated-token-43-chars-base64url-aaaaaaaaa"

	require.NoError(t, tp.Rotate(t.Context(), newTok))
	assert.Equal(t, newTok, tp.Token(), "in-memory token must reflect the rotation")

	// Reload from disk: the persisted plist must carry the rotated token.
	loaded, err := loadPersisted(tokenFile)
	require.NoError(t, err)
	assert.Equal(t, newTok, loaded.HostToken)
	assert.Equal(t, "host-1", loaded.HostID, "rotation must not change host_id")
}

// Empty newToken is a programmer error; Rotate fails fast and leaves
// the existing token in place. The on-disk file is also untouched.
func TestRotate_EmptyTokenRejected(t *testing.T) {
	tp, tokenFile := newTestProvider(t)
	pre, err := loadPersisted(tokenFile)
	require.NoError(t, err)

	require.Error(t, tp.Rotate(t.Context(), ""))
	assert.Equal(t, "original-token", tp.Token(), "in-memory token must be unchanged after a rejected rotate")
	post, err := loadPersisted(tokenFile)
	require.NoError(t, err)
	assert.Equal(t, pre.HostToken, post.HostToken, "on-disk token must be unchanged after a rejected rotate")
}

// Rotate against a provider with no persisted state (e.g., a panic
// path that constructed a provider without Ensure) must surface as an
// error rather than a nil-pointer panic at write time.
func TestRotate_NoStateRejected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := &provider{opts: Options{Logger: logger}, logger: logger}
	require.Error(t, p.Rotate(context.Background(), "anything"))
}

// File mode is preserved across rotations: the post-rotate plist is
// 0600, matching the post-enroll write.
func TestRotate_FileModePreserved(t *testing.T) {
	tp, tokenFile := newTestProvider(t)
	require.NoError(t, tp.Rotate(t.Context(), "next-token-43-chars-padding-aaaaaaaaaaaa"))
	st, err := os.Stat(tokenFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
}
