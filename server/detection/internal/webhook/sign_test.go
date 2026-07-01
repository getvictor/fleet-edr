package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	const (
		id   = "whd_0192f3c4-5678-7abc-9def-0123456789ab"
		ts   = int64(1_767_225_600)
		body = `{"schema_version":"1.0","event_id":"whd_0192f3c4-5678-7abc-9def-0123456789ab"}`
	)
	secret := []byte("s3cr3t-signing-key")

	// Recompute over the exact id.timestamp.body content with the shared secret; a receiver following the Standard Webhooks
	// convention gets the same value. Re-expressing the signed-content construction here pins it: dropping the id or reordering
	// the parts in Sign would break this independent recomputation.
	t.Run("spec:alert-webhook-delivery/deliveries-carry-a-signed-versioned-payload/the-signature-verifies-with-the-shared-secret-and-differs-by-secret", func(t *testing.T) {
		signedContent := id + "." + strconv.FormatInt(ts, 10) + "." + body
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(signedContent))
		want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))

		got := Sign(id, ts, []byte(body), secret)
		assert.Equal(t, want, got, "signature must be HMAC-SHA256 over id.timestamp.body, base64, v1-prefixed")

		other := Sign(id, ts, []byte(body), []byte("a-different-secret"))
		assert.NotEqual(t, got, other, "a different secret must yield a different signature")
	})

	t.Run("is deterministic and v1-prefixed", func(t *testing.T) {
		first := Sign(id, ts, []byte(body), secret)
		second := Sign(id, ts, []byte(body), secret)
		assert.Equal(t, first, second, "same inputs must yield the same signature")
		require.True(t, strings.HasPrefix(first, "v1,"), "signature must carry the v1 scheme prefix")
	})

	t.Run("binds the timestamp", func(t *testing.T) {
		assert.NotEqual(t, Sign(id, ts, []byte(body), secret), Sign(id, ts+1, []byte(body), secret),
			"changing the timestamp must change the signature so receivers can reject replays")
	})
}
