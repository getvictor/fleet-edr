package enrollment

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"
)

// Handler serves POST /api/v1/enroll. Unauthenticated; rate-limited per source IP; emits an
// audit log + OTel span attribute set for every enrollment attempt.
type Handler struct {
	store    *Store
	secret   string
	logger   *slog.Logger
	limiter  *ipLimiter
	trimHost bool // net.SplitHostPort applied in remoteIP; toggleable for tests
}

// Options control handler behaviour.
type Options struct {
	// EnrollSecret is the shared secret the agent presents. Required.
	EnrollSecret string
	// RatePerMinute is the per-source-IP enrollment attempt cap. Defaults to 30.
	RatePerMinute int
	// Logger for audit lines.
	Logger *slog.Logger
}

// NewHandler builds an enrollment handler. Panics if EnrollSecret is empty — the operator
// has to explicitly configure it via EDR_ENROLL_SECRET.
func NewHandler(store *Store, opts Options) *Handler {
	if opts.EnrollSecret == "" {
		panic("enrollment.NewHandler: EnrollSecret must not be empty")
	}
	if opts.RatePerMinute <= 0 {
		opts.RatePerMinute = 30
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		store:    store,
		secret:   opts.EnrollSecret,
		logger:   logger,
		limiter:  newIPLimiter(rate.Every(time.Minute/time.Duration(opts.RatePerMinute)), opts.RatePerMinute),
		trimHost: true,
	}
}

// RegisterRoutes wires the enrollment endpoint onto the mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/enroll", h.handleEnroll)
}

// enrollRequest is the wire payload. NOTE: its String()/fmt.%v must NEVER include the secret —
// we override it below to be safe against accidental log formatting.
type enrollRequest struct {
	EnrollSecret string `json:"enroll_secret"`
	HardwareUUID string `json:"hardware_uuid"`
	Hostname     string `json:"hostname"`
	OSVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
}

// String redacts the enroll secret. Guards against a future `slog.Info("got req", "req", r)`.
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

type enrollErrorBody struct {
	Error string `json:"error"`
}

// uuidPattern accepts standard UUID formats (with or without hyphens, any case). A stricter
// canonical form is too aggressive: macOS IOPlatformUUID is uppercase with hyphens, but
// future platforms may differ.
var uuidPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

func (h *Handler) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("edr.remote_addr", r.RemoteAddr))

	ip := remoteIP(r, h.trimHost)
	if !h.limiter.allow(ip) {
		w.Header().Set("Retry-After", "60")
		h.failf(ctx, w, http.StatusTooManyRequests, "rate_limited", "", ip, "",
			"edr.enroll.reason", "rate_limited")
		return
	}

	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.failf(ctx, w, http.StatusBadRequest, "bad_body", "", ip, "",
			"edr.enroll.reason", "bad_body", "err", err.Error())
		return
	}
	// Fast field-presence check — we want a single "bad_body" code for any shape issue.
	if req.EnrollSecret == "" || req.HardwareUUID == "" || req.Hostname == "" ||
		req.OSVersion == "" || req.AgentVersion == "" {
		h.failf(ctx, w, http.StatusBadRequest, "bad_body", "", ip, "",
			"edr.enroll.reason", "bad_body", "missing_fields", true)
		return
	}
	if !uuidPattern.MatchString(req.HardwareUUID) {
		h.failf(ctx, w, http.StatusBadRequest, "hardware_uuid_invalid", "", ip, "",
			"edr.enroll.reason", "hardware_uuid_invalid")
		return
	}
	// Constant-time secret compare. Never log or span-attribute the secret value.
	if subtle.ConstantTimeCompare([]byte(req.EnrollSecret), []byte(h.secret)) != 1 {
		h.failf(ctx, w, http.StatusUnauthorized, "secret_mismatch", req.HardwareUUID, ip, req.AgentVersion,
			"edr.enroll.reason", "secret_mismatch")
		return
	}

	result, err := h.store.Register(ctx, RegisterRequest{
		HostID:       req.HardwareUUID,
		Hostname:     req.Hostname,
		AgentVersion: req.AgentVersion,
		OSVersion:    req.OSVersion,
		SourceIP:     ip,
	})
	if err != nil {
		h.logger.ErrorContext(ctx, "enroll register", "err", err)
		h.failf(ctx, w, http.StatusInternalServerError, "internal", req.HardwareUUID, ip, req.AgentVersion,
			"edr.enroll.reason", "internal")
		return
	}

	span.SetAttributes(
		attribute.String("edr.enroll.result", "success"),
		attribute.String("edr.host_id", result.HostID),
		attribute.String("edr.agent_version", req.AgentVersion),
		attribute.String("edr.os_version", req.OSVersion),
	)
	h.logger.InfoContext(ctx, "enrolled",
		"edr.enroll.result", "success",
		"edr.host_id", result.HostID,
		"edr.agent_version", req.AgentVersion,
		"edr.os_version", req.OSVersion,
		"edr.remote_addr", ip,
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(enrollResponse{
		HostID:     result.HostID,
		HostToken:  result.HostToken,
		EnrolledAt: result.EnrolledAt,
	})
}

// failf writes a structured JSON error + audit log + span attributes. hostID and agentVersion
// are best-effort; pass "" when the payload failed to parse.
func (h *Handler) failf(
	ctx context.Context, w http.ResponseWriter, status int, code, hostID, ip, agentVersion string,
	logAttrs ...any,
) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("edr.enroll.result", "fail"),
		attribute.Int("http.response.status_code", status),
	)
	if hostID != "" {
		span.SetAttributes(attribute.String("edr.host_id", hostID))
	}
	// Audit at WARN: operators page on suspicious-enroll spikes.
	attrs := append([]any{
		"edr.enroll.result", "fail",
		"edr.remote_addr", ip,
	}, logAttrs...)
	if hostID != "" {
		attrs = append(attrs, "edr.host_id", hostID)
	}
	if agentVersion != "" {
		attrs = append(attrs, "edr.agent_version", agentVersion)
	}
	h.logger.WarnContext(ctx, "enroll failed", attrs...)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(enrollErrorBody{Error: code})
}

// remoteIP extracts a stable IP string from r.RemoteAddr. When trimHost is true (always in
// production) it strips the port; tests that pass "127.0.0.1" directly skip the split.
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

// ipLimiter is a naive per-source-IP rate limiter keyed on the IP string. Each key owns its
// own `rate.Limiter`. The map grows without bound, but MVP fleet sizes and typical pilot
// deployments bound this at low thousands of IPs and we can reap stale entries later.
type ipLimiter struct {
	mu     sync.Mutex
	limit  rate.Limit
	burst  int
	limit2 map[string]*rate.Limiter
}

func newIPLimiter(limit rate.Limit, burst int) *ipLimiter {
	return &ipLimiter{
		limit:  limit,
		burst:  burst,
		limit2: make(map[string]*rate.Limiter),
	}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	rl, ok := l.limit2[ip]
	if !ok {
		rl = rate.NewLimiter(l.limit, l.burst)
		l.limit2[ip] = rl
	}
	return rl.Allow()
}
