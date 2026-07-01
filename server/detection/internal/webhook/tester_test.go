package webhook

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/internal/secretseal"
)

func testTesterSealer(t *testing.T) (*secretseal.Sealer, []byte) {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	s, err := secretseal.NewSealer(key)
	require.NoError(t, err)
	sealed, err := s.Seal([]byte("the-signing-secret"))
	require.NoError(t, err)
	return s, sealed
}

func TestTester_SendTest(t *testing.T) {
	t.Parallel()
	sealer, sealed := testTesterSealer(t)

	t.Run("spec:alert-webhook-delivery/operators-can-test-a-destination-and-see-delivery-health/a-test-delivery-to-a-reachable-receiver-reports-success", func(t *testing.T) {
		t.Parallel()
		var gotSig string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSig = r.Header.Get(HeaderSignature)
			w.WriteHeader(http.StatusOK)
			_ = r.Body.Close()
		}))
		defer srv.Close()
		// Permissive dial control so the test can reach the loopback httptest server; the SSRF guard itself is covered below.
		tester := NewTester(newClient(5*time.Second, 64*1024, allowLoopback), sealer, "https://edr.example.com")
		code, err := tester.SendTest(context.Background(), srv.URL, sealed)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, code)
		assert.Contains(t, gotSig, "v1,", "the test delivery is signed like a real one")
	})

	t.Run("spec:alert-webhook-delivery/operators-can-test-a-destination-and-see-delivery-health/a-test-delivery-to-an-unreachable-receiver-reports-the-error", func(t *testing.T) {
		t.Parallel()
		tester := NewTester(newClient(200*time.Millisecond, 64*1024, allowLoopback), sealer, "")
		// Port 1 on loopback refuses the connection; the permissive control lets the dial proceed to that refusal.
		code, err := tester.SendTest(context.Background(), "https://127.0.0.1:1/hook", sealed)
		require.Error(t, err)
		assert.Zero(t, code)
	})

	t.Run("spec:alert-webhook-delivery/operators-can-test-a-destination-and-see-delivery-health/a-test-delivery-to-an-internal-url-is-blocked-by-the-ssrf-guard", func(t *testing.T) {
		t.Parallel()
		// The production client (real DialControl) refuses to dial a loopback address.
		tester := NewTester(NewClient(2*time.Second, 64*1024), sealer, "")
		code, err := tester.SendTest(context.Background(), "https://127.0.0.1:8080/hook", sealed)
		require.Error(t, err)
		assert.Zero(t, code)
	})

	t.Run("an unopenable secret errors", func(t *testing.T) {
		t.Parallel()
		tester := NewTester(newClient(1*time.Second, 64*1024, allowLoopback), sealer, "")
		code, err := tester.SendTest(context.Background(), "https://x.example.com", []byte("not-a-sealed-blob"))
		require.Error(t, err)
		assert.Zero(t, code)
	})
}
