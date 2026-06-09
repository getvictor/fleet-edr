package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// StateCookieName is the HTTP cookie that carries the per-flow secrets the callback needs to verify. HttpOnly + Secure (in TLS
// deployments) + SameSite=Lax. Lax is REQUIRED - Strict would block the IdP's cross-site GET-redirect that lands the callback.
const StateCookieName = "edr_oidc_state"

// stateClaim is the JSON payload signed into the state cookie. State is the OAuth2 state value (echoed in the AuthURL and the callback
// query string); Nonce is the OIDC nonce verified against the ID token; CodeVerifier is the PKCE secret; Redirect is where to send the
// operator after a successful login. IssuedAt enforces the cookie TTL on the verifier side so a stale cookie is rejected even if the
// browser ignored Max-Age.
type stateClaim struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	Redirect     string `json:"redirect,omitempty"`
	IssuedAt     int64  `json:"iat"`
}

// ErrInvalidStateCookie groups every "you can't trust this cookie" failure into one error type so the handler can map it to a single
// 400 wire shape regardless of which check tripped. Specific reasons are surfaced via Wrapped().
var ErrInvalidStateCookie = errors.New("oidc: state cookie invalid")

// EncodeStateClaim serializes c into "<base64url(json)>.<base64url(sig)>" where sig = HMAC-SHA256(payload64, key). The cookie is not
// confidential - payload64 is plain JSON over base64 so anyone holding the cookie can read state + nonce + code_verifier - but it IS
// authenticated against the signing key. An attacker who replays the cookie at a different IdP or with a swapped state value gets a
// signature mismatch on decode.
func EncodeStateClaim(key []byte, state, nonce, codeVerifier, redirect string, now time.Time) (string, error) {
	payload, err := json.Marshal(stateClaim{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		Redirect:     redirect,
		IssuedAt:     now.Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("oidc: marshal state: %w", err)
	}
	payload64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write([]byte(payload64)); err != nil {
		return "", fmt.Errorf("oidc: hmac state: %w", err)
	}
	sig64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload64 + "." + sig64, nil
}

// DecodedState is the state cookie's payload after signature + TTL
// verification.
type DecodedState struct {
	State        string
	Nonce        string
	CodeVerifier string
	Redirect     string
}

// DecodeStateClaim verifies the cookie's signature with key, checks the IssuedAt against (now, ttl), and returns the decoded payload.
// Any failure (malformed, bad signature, expired) returns ErrInvalidStateCookie wrapped with a more specific reason for the handler's
// slog line.
func DecodeStateClaim(key []byte, cookie string, now time.Time, ttl time.Duration) (*DecodedState, error) {
	dot := strings.IndexByte(cookie, '.')
	if dot <= 0 || dot == len(cookie)-1 {
		return nil, fmt.Errorf("%w: malformed", ErrInvalidStateCookie)
	}
	payload64 := cookie[:dot]
	sig64 := cookie[dot+1:]
	gotSig, err := base64.RawURLEncoding.DecodeString(sig64)
	if err != nil {
		return nil, fmt.Errorf("%w: signature decode", ErrInvalidStateCookie)
	}
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write([]byte(payload64)); err != nil {
		return nil, fmt.Errorf("%w: hmac compute", ErrInvalidStateCookie)
	}
	wantSig := mac.Sum(nil)
	if subtle.ConstantTimeCompare(gotSig, wantSig) != 1 {
		return nil, fmt.Errorf("%w: signature mismatch", ErrInvalidStateCookie)
	}
	payload, err := base64.RawURLEncoding.DecodeString(payload64)
	if err != nil {
		return nil, fmt.Errorf("%w: payload decode", ErrInvalidStateCookie)
	}
	var c stateClaim
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: payload unmarshal", ErrInvalidStateCookie)
	}
	if c.State == "" || c.Nonce == "" || c.CodeVerifier == "" {
		return nil, fmt.Errorf("%w: missing required claim", ErrInvalidStateCookie)
	}
	issued := time.Unix(c.IssuedAt, 0)
	if now.After(issued.Add(ttl)) {
		return nil, fmt.Errorf("%w: expired", ErrInvalidStateCookie)
	}
	if now.Before(issued.Add(-ttl)) {
		// Future-dated cookie - clock-skew vector. Reject.
		return nil, fmt.Errorf("%w: future-dated", ErrInvalidStateCookie)
	}
	return &DecodedState{
		State:        c.State,
		Nonce:        c.Nonce,
		CodeVerifier: c.CodeVerifier,
		Redirect:     c.Redirect,
	}, nil
}
