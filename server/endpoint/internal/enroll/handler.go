// Enroll handler: POST /api/enroll. Public, rate-limited, validates the
// agent's enroll secret, then delegates to api.Service.Enroll for the
// business logic. Owns the HTTP-flavoured concerns: body parse, body
// cap, rate limit, audit log, span attributes, error mapping.

package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"

	"github.com/fleetdm/edr/server/attrkeys"
	"github.com/fleetdm/edr/server/endpoint/api"
)

const (
	attrEnrollReason = "edr.enroll.reason"
	attrEnrollResult = "edr.enroll.result"
)

// Handler serves POST /api/enroll. Unauthenticated; rate-limited per
// source IP. Audit log + OTel span attributes on every attempt.
type Handler struct {
	svc      api.Service
	logger   *slog.Logger
	limiter  *ipLimiter
	trimHost bool // net.SplitHostPort applied in remoteIP; toggleable for tests
}

// Options control handler behaviour.
type Options struct {
	// RatePerMinute is the per-source-IP enrollment attempt cap. Defaults
	// to 30. The handler does not see the enroll secret directly; that
	// lives inside the Service which receives it at construction time.
	RatePerMinute int
	// Logger for audit lines.
	Logger *slog.Logger
}

// New builds an enroll handler. Panics if svc is nil.
func New(svc api.Service, opts Options) *Handler {
	if svc == nil {
		panic("enroll.New: api.Service must not be nil")
	}
	if opts.RatePerMinute <= 0 {
		opts.RatePerMinute = 30
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		svc:      svc,
		logger:   logger,
		limiter:  newIPLimiter(rate.Every(time.Minute/time.Duration(opts.RatePerMinute)), opts.RatePerMinute),
		trimHost: true,
	}
}

// RegisterRoutes wires POST /api/enroll on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/enroll", h.handleEnroll)
}

// enrollRequest is the wire payload. Field names + JSON tags MUST match
// api.EnrollRequest exactly; this local struct exists only to give us
// a String() method that redacts the secret on accidental log
// formatting.
type enrollRequest struct {
	EnrollSecret string `json:"enroll_secret"`
	HardwareUUID string `json:"hardware_uuid"`
	Hostname     string `json:"hostname"`
	OSVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
}

// String redacts the enroll secret. Guards against a future
// `slog.Info("got req", "req", r)`.
func (r enrollRequest) String() string {
	return "enrollRequest{hardware_uuid=" + r.HardwareUUID + " hostname=" + r.Hostname +
		" os_version=" + r.OSVersion + " agent_version=" + r.AgentVersion +
		" enroll_secret=REDACTED}"
}

type enrollResponse struct {
	HostID     string    `json:"host_id"`
	HostToken  string    `json:"host_token"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

type errBody struct {
	Error string `json:"error"`
}

// maxEnrollBodyBytes caps the enroll request body. /api/enroll is
// public + unauthenticated; decoding directly from an unbounded r.Body
// would let any client burn memory/CPU before field validation. The
// real payload is ~300 bytes; 4 KiB leaves plenty of headroom for
// metadata but closes the DoS vector.
const maxEnrollBodyBytes = 4 << 10

func (h *Handler) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := trace.SpanFromContext(ctx)
	ip := remoteIP(r, h.trimHost)
	span.SetAttributes(attribute.String(attrkeys.RemoteAddr, ip))

	if !h.limiter.allow(ip) {
		w.Header().Set("Retry-After", "60")
		h.failf(ctx, w, http.StatusTooManyRequests, "rate_limited", failInfo{IP: ip},
			attrEnrollReason, "rate_limited")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxEnrollBodyBytes)
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.failf(ctx, w, http.StatusBadRequest, "bad_body", failInfo{IP: ip},
			attrEnrollReason, "bad_body", "err", err.Error())
		return
	}
	if req.EnrollSecret == "" || req.HardwareUUID == "" || req.Hostname == "" ||
		req.OSVersion == "" || req.AgentVersion == "" {
		h.failf(ctx, w, http.StatusBadRequest, "bad_body", failInfo{IP: ip, HostID: req.HardwareUUID},
			attrEnrollReason, "bad_body", "missing_fields", true)
		return
	}

	apiReq := api.EnrollRequest{
		EnrollSecret: req.EnrollSecret,
		HardwareUUID: req.HardwareUUID,
		Hostname:     req.Hostname,
		OSVersion:    req.OSVersion,
		AgentVersion: req.AgentVersion,
	}
	res, err := h.svc.Enroll(ctx, apiReq, ip)
	switch {
	case errors.Is(err, api.ErrInvalidHardwareUUID):
		h.failf(ctx, w, http.StatusBadRequest, "hardware_uuid_invalid", failInfo{IP: ip},
			attrEnrollReason, "hardware_uuid_invalid")
		return
	case errors.Is(err, api.ErrInvalidSecret):
		h.failf(ctx, w, http.StatusUnauthorized, "secret_mismatch",
			failInfo{HostID: req.HardwareUUID, IP: ip, AgentVersion: req.AgentVersion},
			attrEnrollReason, "secret_mismatch")
		return
	case err != nil:
		h.logger.ErrorContext(ctx, "enroll register", "err", err)
		h.failf(ctx, w, http.StatusInternalServerError, "internal",
			failInfo{HostID: req.HardwareUUID, IP: ip, AgentVersion: req.AgentVersion},
			attrEnrollReason, "internal")
		return
	}

	span.SetAttributes(
		attribute.String(attrEnrollResult, "success"),
		attribute.String(attrkeys.HostID, res.HostID),
		attribute.String(attrkeys.AgentVersion, req.AgentVersion),
		attribute.String("edr.os_version", req.OSVersion),
	)
	h.logger.InfoContext(ctx, "enrolled",
		attrEnrollResult, "success",
		attrkeys.HostID, res.HostID,
		attrkeys.AgentVersion, req.AgentVersion,
		"edr.os_version", req.OSVersion,
		attrkeys.RemoteAddr, ip,
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(enrollResponse{
		HostID:     res.HostID,
		HostToken:  res.HostToken,
		EnrolledAt: res.EnrolledAt,
	})
}

// failInfo carries the identity + audit fields for a failed enrollment.
type failInfo struct {
	HostID       string
	IP           string
	AgentVersion string
}

// failf writes a structured JSON error + audit log + span attributes.
func (h *Handler) failf(ctx context.Context, w http.ResponseWriter, status int, code string, info failInfo, logAttrs ...any) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String(attrEnrollResult, "fail"),
		attribute.String(attrEnrollReason, code),
		attribute.Int("http.response.status_code", status),
	)
	if info.HostID != "" {
		span.SetAttributes(attribute.String(attrkeys.HostID, info.HostID))
	}
	attrs := append([]any{
		attrEnrollResult, "fail",
		attrkeys.RemoteAddr, info.IP,
	}, logAttrs...)
	if info.HostID != "" {
		attrs = append(attrs, attrkeys.HostID, info.HostID)
	}
	if info.AgentVersion != "" {
		attrs = append(attrs, attrkeys.AgentVersion, info.AgentVersion)
	}
	h.logger.WarnContext(ctx, "enroll failed", attrs...)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errBody{Error: code})
}

// remoteIP extracts a stable IP string from r.RemoteAddr. trimHost is
// always true in production; tests that pass "127.0.0.1" directly skip
// the split.
func remoteIP(r *http.Request, trimHost bool) string {
	if !trimHost {
		return r.RemoteAddr
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- ipLimiter mirrors the identity package's. Duplicated to avoid a
// cross-package private export; same eviction semantics. Refactor
// candidate post-phase-7 (alongside identity's copy and any future
// per-IP-rate-limit caller).

const (
	bucketIdleTTL = 2 * time.Hour
	maxBuckets    = 1024
)

type ipBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type ipLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	buckets map[string]*ipBucket
}

func newIPLimiter(limit rate.Limit, burst int) *ipLimiter {
	return &ipLimiter{limit: limit, burst: burst, buckets: make(map[string]*ipBucket)}
}

func (l *ipLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > maxBuckets {
		for k, b := range l.buckets {
			if now.Sub(b.lastSeen) > bucketIdleTTL {
				delete(l.buckets, k)
			}
		}
	}
	b, ok := l.buckets[ip]
	if !ok {
		b = &ipBucket{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.buckets[ip] = b
	}
	b.lastSeen = now
	return b.limiter.Allow()
}
