package enrollment

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeRefreshAt(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000_000, 0).UTC()
	cases := []struct {
		name string
		exp  time.Time
		want time.Time
	}{
		{"zero expiry -> zero (no proactive refresh)", time.Time{}, time.Time{}},
		{"past expiry -> zero", now.Add(-time.Hour), time.Time{}},
		{"future expiry -> two-thirds through remaining", now.Add(60 * time.Minute), now.Add(40 * time.Minute)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, computeRefreshAt(now, tc.exp))
		})
	}
}

// refreshFakeServer serves /api/enroll (incrementing token tok-N) and /api/token/refresh. refreshStatus controls the refresh response
// status; on 200 it returns refreshToken. Counters let tests assert call counts without sleeps.
type refreshFakeServer struct {
	enrollCalls   atomic.Int64
	refreshCalls  atomic.Int64
	refreshStatus int
	refreshToken  string
}

func (f *refreshFakeServer) handler(t *testing.T, hostID string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		exp := time.Now().Add(time.Hour).UTC()
		switch r.URL.Path {
		case "/api/enroll":
			n := f.enrollCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"host_id": hostID, "host_token": tokenName(n), "enrolled_at": time.Now().UTC(), "expires_at": exp,
			})
		case "/api/token/refresh":
			f.refreshCalls.Add(1)
			assert.NotEmpty(t, r.Header.Get("Authorization"), "refresh must carry the bearer token")
			if f.refreshStatus != http.StatusOK {
				w.WriteHeader(f.refreshStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"host_id": hostID, "host_token": f.refreshToken, "expires_at": exp,
			})
		default:
			http.NotFound(w, r)
		}
	}
}

func tokenName(n int64) string {
	return fmt.Sprintf("tok-%d", n)
}

func enrollProvider(t *testing.T, serverURL string) *provider {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "enrolled.plist")
	tp, err := Ensure(context.Background(), Options{
		ServerURL:      serverURL,
		EnrollSecret:   "s",
		TokenFile:      tokenFile,
		AllowInsecure:  true,
		HostIDOverride: testUUID,
		Logger:         slog.Default(),
	})
	require.NoError(t, err)
	return tp.(*provider)
}

// setRefreshAt overrides the persisted state's refreshAt so a test can drive the refresh-window gate without waiting. The explicit nil
// guard (with return) is what NilAway needs to prove cur / cur.p are non-nil after state.Load(), which has a nil-return path.
func setRefreshAt(t *testing.T, p *provider, at time.Time) {
	t.Helper()
	cur := p.state.Load()
	if cur == nil || cur.p == nil {
		t.Fatal("setRefreshAt: provider has no persisted state")
		return
	}
	p.state.Store(&persistedState{p: cur.p, refreshAt: at})
}

// TestRefreshOnce_Success: a 200 refresh swaps in the new token + expiry, in memory and on disk.
func TestRefreshOnce_Success(t *testing.T) {
	t.Parallel()
	fake := &refreshFakeServer{refreshStatus: http.StatusOK, refreshToken: "refreshed-token"}
	srv := httptest.NewServer(fake.handler(t, testUUID))
	t.Cleanup(srv.Close)

	p := enrollProvider(t, srv.URL)
	require.Equal(t, tokenName(1), p.Token())

	require.NoError(t, p.refreshOnce(context.Background()))
	assert.Equal(t, "refreshed-token", p.Token())
	assert.Equal(t, int64(1), fake.refreshCalls.Load())

	reloaded, err := loadPersisted(p.opts.TokenFile)
	require.NoError(t, err)
	assert.Equal(t, "refreshed-token", reloaded.HostToken)
	assert.False(t, reloaded.ExpiresAt.IsZero(), "refreshed expiry persisted")
}

// spec:agent-enrollment/agent-refreshes-its-token-before-expiry/refresh-after-revocation-re-enrolls
//
// TestRefreshOnce_Unauthorized_ReEnrolls: a 401 refresh falls back to the re-enroll path, yielding a fresh token.
func TestRefreshOnce_Unauthorized_ReEnrolls(t *testing.T) {
	t.Parallel()
	fake := &refreshFakeServer{refreshStatus: http.StatusUnauthorized}
	srv := httptest.NewServer(fake.handler(t, testUUID))
	t.Cleanup(srv.Close)

	p := enrollProvider(t, srv.URL)
	require.Equal(t, tokenName(1), p.Token())

	require.NoError(t, p.refreshOnce(context.Background()))
	assert.Equal(t, tokenName(2), p.Token(), "401 refresh re-enrolled to a fresh token")
	assert.Equal(t, int64(2), fake.enrollCalls.Load())
}

// TestMaybeRefresh covers the refresh-window gate: a no-op before refreshAt, an actual refresh once refreshAt has passed.
func TestMaybeRefresh(t *testing.T) {
	t.Parallel()
	fake := &refreshFakeServer{refreshStatus: http.StatusOK, refreshToken: "ref-tok"}
	srv := httptest.NewServer(fake.handler(t, testUUID))
	t.Cleanup(srv.Close)
	p := enrollProvider(t, srv.URL)

	setRefreshAt(t, p, time.Now().Add(time.Hour))
	p.maybeRefresh(context.Background())
	assert.Equal(t, tokenName(1), p.Token(), "not refreshed before refreshAt")
	assert.Equal(t, int64(0), fake.refreshCalls.Load())

	setRefreshAt(t, p, time.Now().Add(-time.Minute))
	p.maybeRefresh(context.Background())
	assert.Equal(t, "ref-tok", p.Token(), "refreshed once refreshAt passed")
	assert.Equal(t, int64(1), fake.refreshCalls.Load())
}

// TestRunRefresh_ImmediateThenCancel covers the loop's immediate-on-entry check (a due token is refreshed without waiting a tick) and
// the ctx-cancel exit.
func TestRunRefresh_ImmediateThenCancel(t *testing.T) {
	t.Parallel()
	fake := &refreshFakeServer{refreshStatus: http.StatusOK, refreshToken: "ref-tok"}
	srv := httptest.NewServer(fake.handler(t, testUUID))
	t.Cleanup(srv.Close)
	p := enrollProvider(t, srv.URL)
	setRefreshAt(t, p, time.Now().Add(-time.Minute)) // due immediately

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.RunRefresh(ctx); close(done) }()
	require.Eventually(t, func() bool { return p.Token() == "ref-tok" }, 2*time.Second, 10*time.Millisecond)
	cancel()
	<-done
}
