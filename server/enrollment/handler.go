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

	"github.com/fleetdm/edr/server/policy"
	"github.com/fleetdm/edr/server/store"
)

// PolicyGetter is the minimal read interface the enrollment handler needs to queue an
// initial set_blocklist command at first enroll. Kept as an interface so tests can inject
// a stub without pulling in a real MySQL instance or the seed migration.
type PolicyGetter interface {
	Get(ctx context.Context, name string) (*policy.Policy, error)
}

// CommandInserter is the narrow interface the enrollment handler needs to queue the
// initial set_blocklist. Same interface lives in admin.CommandInserter; duplicating it
// here keeps enrollment free of a dependency on the admin package.
type CommandInserter interface {
	InsertCommand(ctx context.Context, c store.Command) (int64, error)
}

// Handler serves POST /api/v1/enroll. Unauthenticated; rate-limited per source IP; emits an
// audit log + OTel span attribute set for every enrollment attempt.
type Handler struct {
	store    *Store
	secret   string
	logger   *slog.Logger
	limiter  *ipLimiter
	trimHost bool            // net.SplitHostPort applied in remoteIP; toggleable for tests
	policy   PolicyGetter    // optional — if nil, no post-enroll fan-out
	commands CommandInserter // optional — must be non-nil if policy is set
}

// Options control handler behaviour.
type Options struct {
	// EnrollSecret is the shared secret the agent presents. Required.
	EnrollSecret string
	// RatePerMinute is the per-source-IP enrollment attempt cap. Defaults to 30.
	RatePerMinute int
	// Logger for audit lines.
	Logger *slog.Logger
	// PolicyStore is the read-only view used to queue a set_blocklist command on first
	// enroll. Optional — leave nil (e.g. in tests) to skip the fan-out. When set,
	// CommandStore must also be set.
	PolicyStore PolicyGetter
	// CommandStore is used to insert the initial set_blocklist command. See PolicyStore.
	CommandStore CommandInserter
}

// NewHandler builds an enrollment handler. Panics if EnrollSecret is empty — the operator
// has to explicitly configure it via EDR_ENROLL_SECRET. Panics if PolicyStore is set but
// CommandStore is not: the two fields must be used together.
func NewHandler(store *Store, opts Options) *Handler {
	if opts.EnrollSecret == "" {
		panic("enrollment.NewHandler: EnrollSecret must not be empty")
	}
	if opts.PolicyStore != nil && opts.CommandStore == nil {
		panic("enrollment.NewHandler: PolicyStore set but CommandStore is nil")
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
		policy:   opts.PolicyStore,
		commands: opts.CommandStore,
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

// uuidPattern accepts the canonical hyphenated UUID form in either case. macOS IOPlatformUUID
// is always uppercase-hyphenated, so that is what agents send today; if a future platform
// emits unhyphenated 32-hex strings, broaden this regex along with a matching agent change.
var uuidPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// maxEnrollBodyBytes caps the enroll request body. /api/v1/enroll is a public, unauthenticated
// endpoint; decoding directly from an unbounded r.Body would let any client burn memory/CPU
// before field validation. The real payload is ~300 bytes; 4 KiB leaves plenty of headroom for
// metadata but closes the DoS vector.
const maxEnrollBodyBytes = 4 << 10

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

	r.Body = http.MaxBytesReader(w, r.Body, maxEnrollBodyBytes)
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

	// Phase 2: queue an initial set_blocklist command AFTER responding so the enroll
	// request's tail latency is not coupled to the policy store + command insert. The
	// detached context keeps the DB writes alive even if the client drops the connection
	// (a transient TLS glitch shouldn't make the host miss its first policy). A failure
	// here is non-fatal: the next admin policy push re-converges any host whose initial
	// command didn't land.
	//
	// Using a detached background context rather than the request ctx so client
	// cancellation doesn't abort the best-effort fanout; capped at 10s to match the
	// outer HTTP server's write timeout + some slack. gosec G118 flags this pattern —
	// the nolint below is the honest marker that we intentionally decouple the
	// background work from the request lifetime.
	go func(hostID string) { //nolint:gosec // G118: intentional detached context so best-effort fanout survives client cancellation.
		bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		h.enqueueInitialPolicy(bgCtx, hostID)
	}(result.HostID)
}

// enqueueInitialPolicy fetches the current default policy and queues a set_blocklist
// command for the newly-enrolled host. Silent on all failures (best-effort) — enrollment
// already succeeded, so the operator is not held up by a flaky command insert; the next
// policy PUT will re-converge the host anyway. Logs at warn so the failure is still
// visible in SigNoz if a class of hosts systematically fails this step.
//
// Skips enqueue entirely when the seeded / current policy is empty (no paths AND no
// hashes): agents with no prior policy state gain nothing from an "apply empty blocklist"
// command, and the command would just round-trip for no effect. The next PUT that adds
// entries will fan out to this host via the admin endpoint's ActiveHostIDs walk.
func (h *Handler) enqueueInitialPolicy(ctx context.Context, hostID string) {
	if h.policy == nil || h.commands == nil {
		return
	}
	p, err := h.policy.Get(ctx, policy.DefaultName)
	if err != nil {
		h.logger.WarnContext(ctx, "initial policy fetch failed", "edr.host_id", hostID, "err", err)
		return
	}
	if len(p.Blocklist.Paths) == 0 && len(p.Blocklist.Hashes) == 0 {
		// Seed policy (v1 empty) or operator explicitly cleared. Nothing to push.
		h.logger.InfoContext(ctx, "initial policy skipped — blocklist empty",
			"edr.host_id", hostID, "edr.policy.version", p.Version)
		return
	}
	payload, err := json.Marshal(policyCommandPayload{
		Name:    p.Name,
		Version: p.Version,
		Paths:   p.Blocklist.Paths,
		Hashes:  p.Blocklist.Hashes,
	})
	if err != nil {
		h.logger.WarnContext(ctx, "initial policy marshal failed", "edr.host_id", hostID, "err", err)
		return
	}
	if _, err := h.commands.InsertCommand(ctx, store.Command{
		HostID:      hostID,
		CommandType: "set_blocklist",
		Payload:     payload,
	}); err != nil {
		h.logger.WarnContext(ctx, "initial policy enqueue failed", "edr.host_id", hostID, "err", err)
		return
	}
	h.logger.InfoContext(ctx, "initial policy queued",
		"edr.host_id", hostID,
		"edr.policy.version", p.Version,
		"edr.policy.path_count", len(p.Blocklist.Paths),
	)
}

// policyCommandPayload mirrors admin.policyCommandPayload. Duplicated here to avoid the
// import cycle admin → enrollment; any future drift would be caught by a cross-package
// integration test that queues + consumes the payload.
type policyCommandPayload struct {
	Name    string   `json:"name"`
	Version int64    `json:"version"`
	Paths   []string `json:"paths"`
	Hashes  []string `json:"hashes"`
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

// ipLimiter is a per-source-IP rate limiter keyed on the IP string. Each key owns its
// own `rate.Limiter`. We cap the map at `maxBuckets` and evict idle entries older than
// `bucketIdleTTL` when the cap is exceeded, so an attacker rotating source IPs cannot
// turn the brute-force defence into an unbounded-memory-growth vector.

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
	return &ipLimiter{
		limit:   limit,
		burst:   burst,
		buckets: make(map[string]*ipBucket),
	}
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
