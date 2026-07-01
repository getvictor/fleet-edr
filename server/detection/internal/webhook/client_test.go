package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowLoopback is a permissive dial control so the client test can reach an httptest server on 127.0.0.1, which the production
// DialControl blocks. The SSRF guard itself is covered by TestDialControl.
func allowLoopback(_, _ string, _ syscall.RawConn) error { return nil }

func testClient() *Client { return newClient(5*time.Second, 64*1024, allowLoopback) }

func TestClient_DeliverSignsAndPosts(t *testing.T) {
	t.Parallel()
	secret := []byte("shared-secret")
	// The handler runs on the server goroutine; guard the captured request fields so the test's reads don't race the writes.
	var mu sync.Mutex
	var gotID, gotTS, gotSig, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotID = r.Header.Get(HeaderID)
		gotTS = r.Header.Get(HeaderTimestamp)
		gotSig = r.Header.Get(HeaderSignature)
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	body := []byte(`{"event_id":"whd_1"}`)
	code, err := testClient().Deliver(context.Background(), srv.URL, "whd_1", 1767225600, body, secret)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "whd_1", gotID)
	assert.Equal(t, "1767225600", gotTS)
	assert.Equal(t, string(body), gotBody)

	// The receiver recomputes the signature over id.timestamp.body and it matches what the client sent.
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(gotID + "." + gotTS + "." + gotBody))
	want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	assert.Equal(t, want, gotSig)
}

// spec:alert-webhook-delivery/outbound-delivery-is-protected-against-ssrf/a-redirect-to-an-internal-target-is-not-followed
func TestClient_DoesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	var reached bool
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, internal.URL, http.StatusFound)
	}))
	defer redirector.Close()

	code, err := testClient().Deliver(context.Background(), redirector.URL, "whd_2", 1, []byte(`{}`), []byte("s"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, code, "the 3xx is returned as-is")
	assert.False(t, reached, "the redirect target must not be dialed")
}

func TestClient_BoundedResponseRead(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		buf := make([]byte, 4096)
		for range 64 {
			_, _ = w.Write(buf) // 256KiB, larger than the 64KiB read cap
		}
	}))
	defer srv.Close()

	code, err := testClient().Deliver(context.Background(), srv.URL, "whd_3", 1, []byte(`{}`), []byte("s"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusAccepted, code)
}
