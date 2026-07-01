package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
)

// Standard Webhooks signature headers (standardwebhooks.com). The spec names them webhook-id / webhook-timestamp /
// webhook-signature; these use the canonical HTTP header casing, which is byte-for-byte what net/http transmits and what receivers
// match (HTTP header names are case-insensitive, so a Standard Webhooks verifier reading "webhook-id" still finds "Webhook-Id").
// Receivers recompute the signature over the same id.timestamp.body content and reject a timestamp outside their tolerance window.
const (
	HeaderID        = "Webhook-Id"
	HeaderTimestamp = "Webhook-Timestamp"
	HeaderSignature = "Webhook-Signature"
)

// signatureVersion prefixes the signature value per the Standard Webhooks convention, leaving room for future MAC schemes.
const signatureVersion = "v1"

// Sign returns the Standard Webhooks signature header value for a request. The signed content is the id, the unix timestamp, and the
// exact body bytes joined by ".", and the MAC is HMAC-SHA256 under the destination secret, base64-encoded and prefixed "v1,". The id
// is part of the signed content (not merely a dedup header), matching the Standard Webhooks spec and its off-the-shelf verifiers.
func Sign(id string, timestamp int64, body, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(id))
	mac.Write([]byte("."))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return signatureVersion + "," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
