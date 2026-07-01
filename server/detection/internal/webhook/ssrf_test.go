package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateURL(t *testing.T) {
	t.Parallel()
	t.Run("spec:alert-webhook-delivery/outbound-delivery-is-protected-against-ssrf/a-non-https-destination-url-is-rejected-on-save", func(t *testing.T) {
		t.Parallel()
		for _, raw := range []string{"http://example.com/hook", "ftp://example.com", "https:///nohost"} {
			assert.ErrorIs(t, ValidateURL(raw), ErrBlockedURL, "must reject %q", raw)
		}
	})

	t.Run("spec:alert-webhook-delivery/outbound-delivery-is-protected-against-ssrf/a-destination-resolving-to-a-private-address-is-rejected-on-save", func(t *testing.T) {
		t.Parallel()
		for _, raw := range []string{
			"https://127.0.0.1/hook",
			"https://10.0.0.5/hook",
			"https://192.168.1.10/hook",
			"https://169.254.169.254/latest/meta-data",
			"https://[::1]/hook",
			"https://[fd00::1]/hook",
			"https://[::ffff:169.254.169.254]/hook",
		} {
			assert.ErrorIs(t, ValidateURL(raw), ErrBlockedURL, "must reject blocked literal %q", raw)
		}
	})

	t.Run("accepts an https public hostname", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, ValidateURL("https://hooks.example.com/webhooks/edr"))
	})
}

func TestDialControl(t *testing.T) {
	t.Parallel()
	t.Run("spec:alert-webhook-delivery/outbound-delivery-is-protected-against-ssrf/a-host-that-resolves-to-the-metadata-address-at-send-time-is-not-delivered", func(t *testing.T) {
		t.Parallel()
		blocked := []string{
			"169.254.169.254:443", // cloud instance-metadata
			"127.0.0.1:443",
			"10.1.2.3:443",
			"[::1]:443",
			"[::ffff:169.254.169.254]:443", // IPv4-mapped IPv6 form of the metadata address
		}
		for _, addr := range blocked {
			err := DialControl("tcp", addr, nil)
			require.Error(t, err, "must refuse to dial %q", addr)
			assert.Contains(t, err.Error(), "blocked address")
		}
	})

	t.Run("allows a public address", func(t *testing.T) {
		t.Parallel()
		for _, addr := range []string{"8.8.8.8:443", "[2606:4700:4700::1111]:443"} {
			assert.NoError(t, DialControl("tcp", addr, nil), "must allow %q", addr)
		}
	})

	t.Run("rejects an unparseable dial address", func(t *testing.T) {
		t.Parallel()
		assert.Error(t, DialControl("tcp", "not-an-address", nil))
	})
}

// TestBlockedURLErrorIsSentinel guards that callers can branch on the sentinel rather than string-matching.
func TestBlockedURLErrorIsSentinel(t *testing.T) {
	t.Parallel()
	assert.ErrorIs(t, ValidateURL("http://x"), ErrBlockedURL)
}
