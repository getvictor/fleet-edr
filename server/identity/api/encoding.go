package api

import "encoding/base64"

// EncodeToken serialises raw session or CSRF token bytes to the on-wire
// form (cookie value or X-Csrf-Token header). Always emits raw-unpadded
// base64url.
func EncodeToken(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeToken parses an on-wire token into its raw bytes. Accepts both
// raw-unpadded (the form we emit) and padded base64url; some middleboxes
// rewrite trailing '=' so we accept either rather than locking customers
// out.
func DecodeToken(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
