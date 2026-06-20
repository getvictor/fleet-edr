package saadmin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/satoken"
	"github.com/fleetdm/edr/server/identity/internal/serviceaccounts"
)

const (
	// accessTokenTTL is the lifetime of a minted service-account access token (ADR-0013). Short so the per-replica revocation snapshot
	// is a backstop rather than the primary control; clients re-run the grant near expiry.
	accessTokenTTL = 15 * time.Minute

	// defaultRateLimit is the per-client-id token-request budget per minute. Generous for a well-behaved client (which mints roughly
	// once per TTL) but bounds credential brute-force and DoS against the credential-exchange endpoint.
	defaultRateLimit  = 60
	rateLimitWindow   = time.Minute
	maxTokenBodyBytes = 8 << 10
	// maxClientIDLen bounds the client_id before it is used as a rate-limiter map key, so an attacker can't grow per-key memory with
	// oversized keys. Real client ids are "sa_" + 16 hex = 19 chars.
	maxClientIDLen = 64
	// maxLimiterKeys caps the rate-limiter map so a flood of unique client_ids on this public endpoint cannot grow memory without
	// bound; once full, new keys are refused rather than admitted.
	maxLimiterKeys = 10_000
)

// TokenStore is the persistence the token endpoint needs.
type TokenStore interface {
	AuthByClientID(ctx context.Context, clientID string) (serviceaccounts.AuthRecord, error)
	MarkUsed(ctx context.Context, clientID string) error
}

// Minter mints an access token; implemented by *satoken.Signer.
type Minter interface {
	Mint(in satoken.MintInput, ttl time.Duration, now time.Time) (string, time.Time, error)
}

// TokenHandler serves POST /api/oauth/token: the OAuth 2.1 client-credentials grant. It authenticates by the presented credential
// (not a session cookie or host token), so it mounts on the public mux and is CSRF-exempt; it rate-limits per client id.
type TokenHandler struct {
	store   TokenStore
	minter  Minter
	audit   AuditRecorder
	logger  *slog.Logger
	limiter *rateLimiter
	now     func() time.Time
}

// NewTokenHandler constructs the token endpoint handler.
func NewTokenHandler(store TokenStore, minter Minter, audit AuditRecorder, logger *slog.Logger) *TokenHandler {
	if logger == nil {
		logger = slog.Default()
	}
	now := time.Now
	return &TokenHandler{
		store:   store,
		minter:  minter,
		audit:   audit,
		logger:  logger,
		limiter: newRateLimiter(defaultRateLimit, rateLimitWindow, now),
		now:     now,
	}
}

// RegisterPublicRoutes mounts the token endpoint on the root mux (no session / host-token middleware).
func (h *TokenHandler) RegisterPublicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/oauth/token", h.handleToken)
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (h *TokenHandler) handleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID, secret, ok := parseCredentials(r)
	if !ok || clientID == "" || secret == "" || len(clientID) > maxClientIDLen {
		// Bound the client_id length here, before it is used as a rate-limiter map key or hits the DB, so oversized/garbage ids are
		// rejected cheaply.
		writeErr(ctx, h.logger, w, http.StatusBadRequest, "invalid_request")
		return
	}
	// Rate-limit before the DB lookup so a flood is cheap to refuse.
	if !h.limiter.allow(clientID) {
		writeErr(ctx, h.logger, w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	rec, err := h.store.AuthByClientID(ctx, clientID)
	if errors.Is(err, serviceaccounts.ErrNotFound) {
		// Unknown client, revoked, expired, and bad secret all collapse to one opaque 401 (no oracle for which part was wrong).
		writeErr(ctx, h.logger, w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if err != nil {
		h.logger.ErrorContext(ctx, "service-account token lookup", "err", err)
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if !h.credentialValid(rec, secret) {
		writeErr(ctx, h.logger, w, http.StatusUnauthorized, "invalid_client")
		return
	}
	now := h.now().UTC()
	token, exp, err := h.minter.Mint(satoken.MintInput{Subject: rec.ClientID, Role: rec.RoleID, Epoch: rec.Epoch}, accessTokenTTL, now)
	if err != nil {
		h.logger.ErrorContext(ctx, "service-account token mint", "err", err)
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if err := h.store.MarkUsed(ctx, rec.ClientID); err != nil {
		h.logger.WarnContext(ctx, "service-account mark used failed", "err", err)
	}
	h.recordIssuance(ctx, r, rec.ClientID)
	httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusOK, tokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(exp.Sub(now).Seconds()),
	})
}

// credentialValid reports whether the record is usable (not revoked, not expired) and the presented secret matches, in constant time
// for the secret compare.
func (h *TokenHandler) credentialValid(rec serviceaccounts.AuthRecord, secret string) bool {
	if rec.RevokedAt.Valid {
		return false
	}
	if !rec.ExpiresAt.After(h.now()) {
		return false
	}
	return serviceaccounts.SecretMatches(rec.SecretHash, secret)
}

func (h *TokenHandler) recordIssuance(ctx context.Context, r *http.Request, clientID string) {
	if h.audit == nil {
		return
	}
	if err := h.audit.Record(ctx, api.AuditEvent{
		Action:     api.AuditAction("service_account.token_issued"),
		TargetType: "service_account",
		TargetID:   clientID,
		RemoteAddr: httpserver.ClientIP(r),
	}); err != nil {
		h.logger.ErrorContext(ctx, "service-account issuance audit failed", "err", err)
	}
}

// parseCredentials reads client_id + client_secret from either a JSON body or a form-encoded body (the OAuth 2.1 standard). When a
// grant_type is supplied it must be client_credentials.
func parseCredentials(r *http.Request) (clientID, secret string, ok bool) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var body struct {
			GrantType    string `json:"grant_type"`
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		// io.LimitReader, not http.MaxBytesReader: the latter requires a non-nil http.ResponseWriter and we have none here. The bound
		// is all we need; an over-limit body simply truncates and fails to decode.
		dec := json.NewDecoder(io.LimitReader(r.Body, maxTokenBodyBytes))
		if err := dec.Decode(&body); err != nil {
			return "", "", false
		}
		if body.GrantType != "" && body.GrantType != "client_credentials" {
			return "", "", false
		}
		return strings.TrimSpace(body.ClientID), body.ClientSecret, true
	}
	r.Body = io.NopCloser(io.LimitReader(r.Body, maxTokenBodyBytes))
	if err := r.ParseForm(); err != nil {
		return "", "", false
	}
	if gt := r.PostForm.Get("grant_type"); gt != "" && gt != "client_credentials" {
		return "", "", false
	}
	return strings.TrimSpace(r.PostForm.Get("client_id")), r.PostForm.Get("client_secret"), true
}

// rateLimiter is a per-key fixed-window limiter. Per-replica and best-effort (ADR-0010): behind N replicas a client gets up to N
// times the budget, which is an accepted bound for a DoS/brute-force guard, not a correctness control.
type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	maxKeys int
	window  time.Duration
	now     func() time.Time
	// seen is a per-replica perf cache, safe to lose: it holds only in-window request counts and is bounded by maxKeys.
	seen map[string]*windowCounter
}

type windowCounter struct {
	count   int
	resetAt time.Time
}

func newRateLimiter(limit int, window time.Duration, now func() time.Time) *rateLimiter {
	return &rateLimiter{limit: limit, maxKeys: maxLimiterKeys, window: window, now: now, seen: map[string]*windowCounter{}}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	if c, ok := rl.seen[key]; ok && !now.After(c.resetAt) {
		if c.count >= rl.limit {
			return false
		}
		c.count++
		return true
	}
	// New or expired window for this key. Keep the common path O(1): only scan-to-prune when the map is at its cap, and once it is
	// still full after pruning, refuse new keys rather than grow without bound under a unique-key flood.
	if len(rl.seen) >= rl.maxKeys {
		rl.pruneLocked(now)
		if len(rl.seen) >= rl.maxKeys {
			return false
		}
	}
	rl.seen[key] = &windowCounter{count: 1, resetAt: now.Add(rl.window)}
	return true
}

// pruneLocked drops expired windows. Caller holds the lock. Called only when the map reaches its cap, so it is amortized rather than
// run on every new key.
func (rl *rateLimiter) pruneLocked(now time.Time) {
	for k, c := range rl.seen {
		if now.After(c.resetAt) {
			delete(rl.seen, k)
		}
	}
}
