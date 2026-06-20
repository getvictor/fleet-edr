package saadmin

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/satoken"
	"github.com/fleetdm/edr/server/identity/internal/serviceaccounts"
)

var fixedNow = time.Unix(1_700_000_000, 0)

type fakeTokenStore struct {
	rec    serviceaccounts.AuthRecord
	err    error
	marked bool
}

func (f *fakeTokenStore) AuthByClientID(context.Context, string) (serviceaccounts.AuthRecord, error) {
	if f.err != nil {
		return serviceaccounts.AuthRecord{}, f.err
	}
	return f.rec, nil
}

func (f *fakeTokenStore) MarkUsed(context.Context, string) error {
	f.marked = true
	return nil
}

type fakeMinter struct{ token string }

func (f fakeMinter) Mint(_ satoken.MintInput, ttl time.Duration, now time.Time) (string, time.Time, error) {
	return f.token, now.Add(ttl), nil
}

func newTokenH(store TokenStore, audit AuditRecorder) *TokenHandler {
	h := NewTokenHandler(store, fakeMinter{token: "minted.access.token"}, audit, nil)
	h.now = func() time.Time { return fixedNow }
	h.limiter = newRateLimiter(defaultRateLimit, rateLimitWindow, h.now)
	return h
}

func validRecord(secret string) serviceaccounts.AuthRecord {
	sum := sha256.Sum256([]byte(secret))
	return serviceaccounts.AuthRecord{
		ClientID: "sa_abc", RoleID: "analyst", SecretHash: sum[:], Epoch: 0,
		ExpiresAt: fixedNow.Add(time.Hour),
	}
}

func jsonTokenReq(t *testing.T, clientID, secret string) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]string{"grant_type": "client_credentials", "client_id": clientID, "client_secret": secret})
	require.NoError(t, err)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/oauth/token", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestToken_validCredentialMintsToken(t *testing.T) {
	t.Parallel()
	store := &fakeTokenStore{rec: validRecord("edrsa_good")}
	audit := &captureAudit{}
	h := newTokenH(store, audit)
	w := httptest.NewRecorder()
	h.handleToken(w, jsonTokenReq(t, "sa_abc", "edrsa_good"))

	require.Equal(t, http.StatusOK, w.Code)
	var resp tokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "minted.access.token", resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, int(accessTokenTTL.Seconds()), resp.ExpiresIn)
	assert.True(t, store.marked, "successful issuance stamps last_used")
	require.Len(t, audit.events, 1)
	assert.Equal(t, api.AuditAction("service_account.token_issued"), audit.events[0].Action)
	assert.NotContains(t, w.Body.String(), "edrsa_good", "the response never echoes the secret")
}

func TestToken_formEncoded(t *testing.T) {
	t.Parallel()
	store := &fakeTokenStore{rec: validRecord("edrsa_good")}
	h := newTokenH(store, &captureAudit{})
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"sa_abc"}, "client_secret": {"edrsa_good"}}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.handleToken(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestToken_rejections(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		store  *fakeTokenStore
		secret string
		status int
		reason string
	}{
		{"bad secret", &fakeTokenStore{rec: validRecord("edrsa_good")}, "edrsa_wrong", http.StatusUnauthorized, "invalid_client"},
		{"unknown client", &fakeTokenStore{err: serviceaccounts.ErrNotFound}, "edrsa_x", http.StatusUnauthorized, "invalid_client"},
		{
			"revoked",
			&fakeTokenStore{rec: func() serviceaccounts.AuthRecord {
				r := validRecord("edrsa_good")
				r.RevokedAt = sql.NullTime{Valid: true, Time: fixedNow}
				return r
			}()},
			"edrsa_good", http.StatusUnauthorized, "invalid_client",
		},
		{
			"expired",
			&fakeTokenStore{rec: func() serviceaccounts.AuthRecord {
				r := validRecord("edrsa_good")
				r.ExpiresAt = fixedNow.Add(-time.Hour)
				return r
			}()},
			"edrsa_good", http.StatusUnauthorized, "invalid_client",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newTokenH(tc.store, &captureAudit{})
			w := httptest.NewRecorder()
			h.handleToken(w, jsonTokenReq(t, "sa_abc", tc.secret))
			require.Equal(t, tc.status, w.Code)
			assert.Contains(t, w.Body.String(), tc.reason)
			assert.False(t, tc.store.marked, "a refused request must not stamp last_used")
		})
	}
}

func TestToken_badRequest(t *testing.T) {
	t.Parallel()
	h := newTokenH(&fakeTokenStore{rec: validRecord("edrsa_good")}, &captureAudit{})
	cases := []struct {
		name string
		req  *http.Request
	}{
		{"missing secret", jsonTokenReq(t, "sa_abc", "")},
		{"missing client", jsonTokenReq(t, "", "edrsa_good")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			h.handleToken(w, tc.req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestToken_wrongGrantType(t *testing.T) {
	t.Parallel()
	h := newTokenH(&fakeTokenStore{rec: validRecord("edrsa_good")}, &captureAudit{})
	form := url.Values{"grant_type": {"password"}, "client_id": {"sa_abc"}, "client_secret": {"edrsa_good"}}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.handleToken(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestToken_malformedJSON(t *testing.T) {
	t.Parallel()
	h := newTokenH(&fakeTokenStore{rec: validRecord("edrsa_good")}, &captureAudit{})
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/oauth/token", strings.NewReader("{bad"))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleToken(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestToken_rateLimited(t *testing.T) {
	t.Parallel()
	store := &fakeTokenStore{rec: validRecord("edrsa_good")}
	h := newTokenH(store, &captureAudit{})
	h.limiter = newRateLimiter(1, rateLimitWindow, h.now)
	require.True(t, h.limiter.allow("sa_abc"), "first request consumes the single-token budget")
	w := httptest.NewRecorder()
	h.handleToken(w, jsonTokenReq(t, "sa_abc", "edrsa_good"))
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "rate_limited")
}

func TestRateLimiter(t *testing.T) {
	t.Parallel()
	now := fixedNow
	rl := newRateLimiter(2, time.Minute, func() time.Time { return now })
	assert.True(t, rl.allow("k"))
	assert.True(t, rl.allow("k"))
	assert.False(t, rl.allow("k"), "third request in the window is refused")
	assert.True(t, rl.allow("other"), "a different key has its own budget")

	// After the window elapses, the budget resets.
	now = now.Add(2 * time.Minute)
	assert.True(t, rl.allow("k"))
}
