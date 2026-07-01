package health

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTokens struct {
	token        string
	unauthorized atomic.Int64
}

func (f *fakeTokens) Token() string                  { return f.token }
func (f *fakeTokens) OnUnauthorized(context.Context) { f.unauthorized.Add(1) }

type capturedReq struct {
	auth        string
	contentType string
	body        []byte
}

func newCaptureServer(t *testing.T, status int, hits chan<- capturedReq) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case hits <- capturedReq{auth: r.Header.Get("Authorization"), contentType: r.Header.Get("Content-Type"), body: b}:
		default:
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestPoster(t *testing.T, srv *httptest.Server, tokens TokenSource, reg *Registry) *Poster {
	t.Helper()
	return NewPoster(Options{
		Registry:     reg,
		Client:       srv.Client(),
		BaseURL:      srv.URL,
		Tokens:       tokens,
		AgentVersion: "0.4.0",
		Interval:     20 * time.Millisecond,
		Debounce:     5 * time.Millisecond,
		NowNs:        fixedClock(1234),
	})
}

func TestPoster_PostSendsSnapshot(t *testing.T) {
	t.Parallel()
	hits := make(chan capturedReq, 4)
	srv := newCaptureServer(t, http.StatusNoContent, hits)
	reg := newRegistryWithClock(fixedClock(7))
	reg.Register(ComponentNetworkExtension, "Network extension")
	reg.MarkConnected(ComponentNetworkExtension)
	p := newTestPoster(t, srv, &fakeTokens{token: "tok-abc"}, reg)

	p.post(t.Context())

	req := <-hits
	assert.Equal(t, "Bearer tok-abc", req.auth)
	assert.Equal(t, "application/json", req.contentType)
	var got report
	require.NoError(t, json.Unmarshal(req.body, &got))
	assert.Equal(t, "0.4.0", got.AgentVersion)
	assert.EqualValues(t, 1234, got.ReportedAtNs)
	require.Len(t, got.Components, 1)
	assert.Equal(t, ComponentNetworkExtension, got.Components[0].Type)
	assert.Equal(t, StatusHealthy, got.Components[0].Status)
}

func TestPoster_UnauthorizedTriggersReenroll(t *testing.T) {
	t.Parallel()
	hits := make(chan capturedReq, 1)
	srv := newCaptureServer(t, http.StatusUnauthorized, hits)
	reg := newRegistryWithClock(fixedClock(1))
	reg.Register(ComponentNetworkExtension, "Network extension")
	tokens := &fakeTokens{token: "stale"}
	p := newTestPoster(t, srv, tokens, reg)

	p.post(t.Context())

	assert.EqualValues(t, 1, tokens.unauthorized.Load(), "a 401 must drive the re-enroll path")
}

func TestPoster_NonSuccessIsDroppedNotReenroll(t *testing.T) {
	t.Parallel()
	hits := make(chan capturedReq, 1)
	srv := newCaptureServer(t, http.StatusBadRequest, hits)
	reg := newRegistryWithClock(fixedClock(1))
	reg.Register(ComponentNetworkExtension, "Network extension")
	tokens := &fakeTokens{token: "t"}
	p := newTestPoster(t, srv, tokens, reg)

	p.post(t.Context())

	<-hits // the request was sent
	assert.EqualValues(t, 0, tokens.unauthorized.Load(), "a non-401 rejection is logged and dropped, not a re-enroll trigger")
}

func TestPoster_SkipsWhenNotEnrolled(t *testing.T) {
	t.Parallel()
	var hit atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	reg := newRegistryWithClock(fixedClock(1))
	reg.Register(ComponentNetworkExtension, "Network extension")
	tokens := &fakeTokens{token: ""}
	p := newTestPoster(t, srv, tokens, reg)

	p.post(t.Context())

	assert.False(t, hit.Load(), "no token yet: the poster must not hit the server")
	assert.EqualValues(t, 0, tokens.unauthorized.Load(), "an empty token is not a 401; do not re-enroll")
}

func TestPoster_RunPostsOnStartupTransitionAndStops(t *testing.T) {
	t.Parallel()
	hits := make(chan capturedReq, 16)
	srv := newCaptureServer(t, http.StatusNoContent, hits)
	reg := newRegistryWithClock(seqClock(1))
	reg.Register(ComponentNetworkExtension, "Network extension")
	p := newTestPoster(t, srv, &fakeTokens{token: "t"}, reg)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	// Startup post.
	waitForHit(t, hits)
	// A transition wakes the poster (debounced) for another post.
	reg.MarkConnected(ComponentNetworkExtension)
	waitForHit(t, hits)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

func TestNewPoster_RequiresDependencies(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() {
		NewPoster(Options{Client: &http.Client{}, Tokens: &fakeTokens{}}) // no Registry
	})
}

func TestNewPoster_AppliesDefaults(t *testing.T) {
	t.Parallel()
	p := NewPoster(Options{Registry: NewRegistry(), Client: &http.Client{}, Tokens: &fakeTokens{}})
	assert.Equal(t, defaultPostInterval, p.interval)
	assert.Equal(t, defaultDebounce, p.debounce)
	require.NotNil(t, p.nowNs)
	require.NotNil(t, p.logger)
}

func waitForHit(t *testing.T, hits <-chan capturedReq) {
	t.Helper()
	select {
	case <-hits:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a status check-in post within 2s")
	}
}
