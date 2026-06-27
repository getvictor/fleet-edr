package intake

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/httpserver"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// MaxIngestBodyBytes is the per-request body cap on POST /api/events. The contract is documented in openspec/specs/
// server-event-ingestion/spec.md (Body size limit requirement); see the comment on handleIngest for the enforcement shape.
// Exported for tests that need to compose right-at-cap and over-cap bodies without duplicating the magic number.
const MaxIngestBodyBytes = 10 * 1024 * 1024

// MaxIngestEventsPerRequest caps the number of events the parser accepts in a single batch. Closes the memory-amplification angle that the 10 MB body cap doesn't on its own: a minimal event JSON is ~50 bytes on the wire but the in-memory api.Event representation (json.RawMessage payload + the four string headers) is several hundred bytes. As a result a 10 MB body of microscopic events could expand to ~140k entries and ~60-80 MB of heap before the downstream InsertEvents loop runs. The agent's defaultBatchSize is 100; 10k is two orders of magnitude of headroom for legitimate batching while capping the blast radius of a hostile or buggy peer.
const MaxIngestEventsPerRequest = 10_000

// ParseAndValidateIngestBody is the parse + per-event validation half of POST /api/events, lifted out of handleIngest so the fuzz
// harness can drive it without a full HTTP server + Detection store. Returns (events, http.StatusOK, "") on success, or
// (4xx/5xx, errCode) on parse / validation failure. The error codes are the same stable set the HTTP handler emits:
// "invalid_json", "missing_fields_at_<i>", "host_id_mismatch", "too_many_events". The body-byte cap (413 body_too_large) is
// upstream of this function (in readBodyWithCap); the store-insert (5xx) is downstream. The fuzz contract is therefore: every
// output MUST be one of {(200, ""), (400, "invalid_json"), (400, "missing_fields_at_<i>"), (400, "host_id_mismatch"),
// (413, "too_many_events")}; anything else is a finding.
//
// too_many_events is 413 not 400 (Copilot #276). The agent's uploader classifies 400 as a generic clientError that goes
// through the #253 quarantine path, so a misconfigured agent posting an over-cap batch would have every event in the batch
// sealed as "malformed" after the quarantine threshold instead of split-and-retried. Returning 413 routes the rejection
// through the same split-and-retry recovery as the body-byte cap: the agent bisects the batch and re-posts each half, and
// converges at single-event leaves (the rare case where one event alone exceeds the cap, dropped with the
// events_dropped_too_large metric). Both 413 diagnostics (body_too_large + too_many_events) coexist; operator-facing logs
// distinguish them via the errCode string while the wire status drives the same agent recovery shape.
//
// Streaming-decode shape (CodeRabbit #276 follow-up to #275): the previous shape called json.Unmarshal(body, &events) which
// fully materialises the []api.Event slice before len(events) is checked, so a 10 MB body of microscopic events still allocates
// ~140k api.Event structs (~60-80 MB of heap) before the MaxIngestEventsPerRequest cap fires. The fix is to decode incrementally
// with json.Decoder so the cap aborts the loop before the over-cap event is allocated. The per-event allocation still happens,
// but it's bounded to MaxIngestEventsPerRequest+1, not the entire body's worth.
func ParseAndValidateIngestBody(body []byte, pinnedHostID string) (events []api.Event, status int, errCode string) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if !readArrayOpen(dec) {
		return nil, http.StatusBadRequest, "invalid_json"
	}
	events, status, errCode = streamDecodeEvents(dec, pinnedHostID)
	if status != http.StatusOK {
		return nil, status, errCode
	}
	if !readArrayCloseAndEOF(dec) {
		return nil, http.StatusBadRequest, "invalid_json"
	}
	return events, http.StatusOK, ""
}

// readArrayOpen consumes the opening `[` token. Returns false for anything else (`{`, null, primitive, garbage, EOF). Subsumes
// the previous explicit nil-check on the literal `null` body: json.Decoder.Token() for `null` returns the nil Token, which
// fails the json.Delim type-assert below, so the same input still returns invalid_json. Extracted from
// ParseAndValidateIngestBody so the parent stays under Sonar's S3776 cognitive-complexity budget.
func readArrayOpen(dec *json.Decoder) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	delim, ok := tok.(json.Delim)
	return ok && delim == '['
}

// streamDecodeEvents reads array elements one-at-a-time, applying the cap + per-event validation in a single pass. Returns
// events on success or (status, errCode) on the first validation failure. The cap fires BEFORE the over-cap event is
// allocated; the +1 conceptual margin (accept up to and including MaxIngestEventsPerRequest, reject the (Max+1)th before
// decoding) keeps the heap-amplification path closed even on a body at the 10 MB upstream byte cap.
func streamDecodeEvents(dec *json.Decoder, pinnedHostID string) ([]api.Event, int, string) {
	var events []api.Event
	for i := 0; dec.More(); i++ {
		if i >= MaxIngestEventsPerRequest {
			return nil, http.StatusRequestEntityTooLarge, "too_many_events"
		}
		var e api.Event
		if err := dec.Decode(&e); err != nil {
			return nil, http.StatusBadRequest, "invalid_json"
		}
		if e.EventID == "" || e.HostID == "" || e.EventType == "" || e.TimestampNs == 0 {
			return nil, http.StatusBadRequest, "missing_fields_at_" + strconv.Itoa(i)
		}
		if e.HostID != pinnedHostID {
			return nil, http.StatusBadRequest, "host_id_mismatch"
		}
		events = append(events, e)
	}
	return events, http.StatusOK, ""
}

// readArrayCloseAndEOF verifies the array closes with `]` AND the decoder reaches io.EOF on the next token call. Trailing
// bytes after the array are invalid_json (matching json.Unmarshal's contract). The two checks together reject inputs like
// `[]extra` or `[][]`.
func readArrayCloseAndEOF(dec *json.Decoder) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != ']' {
		return false
	}
	_, err = dec.Token()
	return errors.Is(err, io.EOF)
}

// BuildInfo is injected at startup so the readiness endpoint
// advertises version + commit.
type BuildInfo struct {
	Version   string
	Commit    string
	BuildTime string
}

// Handler serves the event ingestion API plus the
// livez/readyz/health endpoints.
type Handler struct {
	store        *mysql.Store
	eventLog     visibilityapi.EventLog
	eventArchive visibilityapi.EventArchive
	logger       *slog.Logger
	buildInfo    BuildInfo
	startTime    time.Time
	metrics      api.MetricsRecorder
	isDraining   func() bool
}

// New creates an ingestion Handler. eventLog (the work queue) and eventArchive (the durable lake) are the post-cutover event sinks
// (ADR-0015); both are required in full mode. The store argument carries control-plane writes (host summary + snapshot freshness) and
// may be nil in tests that only exercise the health endpoints; readiness checks handle that case explicitly.
func New(s *mysql.Store, logger *slog.Logger, info BuildInfo, eventLog visibilityapi.EventLog, eventArchive visibilityapi.EventArchive) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		store:        s,
		eventLog:     eventLog,
		eventArchive: eventArchive,
		logger:       logger,
		buildInfo:    info,
		startTime:    time.Now(),
	}
}

// SetMetrics installs the OTel ingest-counter hook.
func (h *Handler) SetMetrics(m api.MetricsRecorder) { h.metrics = m }

// SetReadinessGate installs the graceful-shutdown drain predicate. When it returns true, /readyz reports 503 ("draining") so a
// load balancer removes this replica from rotation before the listener closes. cmd/main wires this to the process DrainState; a nil
// gate (the default) means readiness reflects only the DB check.
func (h *Handler) SetReadinessGate(isDraining func() bool) { h.isDraining = isDraining }

// IngestHandler returns the POST /api/events handler. Callers wrap
// it in the endpoint context's HostToken middleware before mounting.
func (h *Handler) IngestHandler() http.Handler {
	return http.HandlerFunc(h.handleIngest)
}

// RegisterHealthRoutes registers the unauthenticated /livez,
// /readyz, /health routes.
func (h *Handler) RegisterHealthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /livez", h.handleLivez)
	mux.HandleFunc("GET /readyz", h.handleReadyz)
	mux.HandleFunc("GET /health", h.handleReadyz)
}

func (h *Handler) handleIngest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	pinnedHostID, ok := endpointapi.HostIDFromContext(ctx)
	if !ok {
		h.logger.ErrorContext(ctx, "ingest handler reached without host_id on context; middleware misconfigured")
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}

	body, ok := h.readBodyWithCap(w, r)
	if !ok {
		return
	}

	events, status, errCode := ParseAndValidateIngestBody(body, pinnedHostID)
	if status != http.StatusOK {
		writeErr(ctx, h.logger, w, status, errCode)
		return
	}

	// Liveness-only events (snapshot_heartbeat) are processed for their freshness side effect and dropped instead of persisted as
	// retained event rows (issue #408): they are ~22% of rows for zero forensic value, and the engine already filters them before
	// rule evaluation. Everything else is persisted exactly as before.
	toStore, heartbeats := partitionHeartbeats(events)

	// Stamp the server-controlled arrival time on every storable event before the fan-out. ingested_at_ns is the clock-drift-tolerant
	// ordering + correlation key (cross-stream rules and the process-detail read window on it), so it MUST come from the server clock,
	// not the agent's: an agent cannot set or skew it. Both stores persist exactly what we stamp here. (Pre-cutover this lived in the
	// MySQL InsertEvents path; the fan-out moved it up to the handler so both the archive and the queue see the same value.)
	ingestedAtNs := time.Now().UnixNano()
	for i := range toStore {
		toStore[i].IngestedAtNs = ingestedAtNs
	}

	// Fan out to the two event stores (ADR-0015), archive FIRST so the durable lake has every event before it is enqueued for
	// processing: the alert-evidence copy reads the archive, and a partial failure leaves nothing queued. Both writes are idempotent by
	// event_id (ReplacingMergeTree on the archive, INSERT IGNORE on the queue), so the agent's retry of a 200-less batch is safe. We
	// return 200 only after BOTH succeed.
	if err := h.eventArchive.Insert(ctx, toStore); err != nil {
		h.logger.ErrorContext(ctx, "archive insert error", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}
	if err := h.eventLog.Append(ctx, toStore); err != nil {
		h.logger.ErrorContext(ctx, "eventlog append error", "err", err)
		writeErr(ctx, h.logger, w, http.StatusInternalServerError, "internal")
		return
	}

	if h.metrics != nil {
		// edr.events.ingested counts the full accepted batch (heartbeats included) to honor its stable-counter contract
		// ("incremented by the size of the batch", observability-instrumentation spec). heartbeats_dropped is the not-persisted
		// subset: every heartbeat in the batch (len(events)-len(toStore)), including malformed/zero-pid ones that produced no bump.
		h.metrics.EventsIngested(ctx, pinnedHostID, len(events))
		h.metrics.EventsHeartbeatDropped(ctx, pinnedHostID, len(events)-len(toStore))
	}

	// Apply the heartbeat freshness bump (the heartbeat's only server-side effect: bump processes.last_seen_ns so the TTL reconciler
	// exempts a live snapshot row). Best-effort like UpsertHosts: a heartbeat lands every reconcile interval, so a transient failure
	// here is re-applied by the next one, well within the 6h TTL. Never fail the batch over a liveness bump.
	if len(heartbeats) > 0 {
		if err := h.store.BumpSnapshotLastSeenBatch(ctx, pinnedHostID, heartbeats); err != nil {
			h.logger.ErrorContext(ctx, "heartbeat freshness bump", "err", err)
		}
	}

	// UpsertHosts sees the full batch (heartbeats included) so per-host last_seen / event_count advance for a near-idle host whose
	// only traffic is heartbeats, exactly as before this change.
	if err := h.store.UpsertHosts(ctx, events); err != nil {
		h.logger.ErrorContext(ctx, "upsert hosts", "err", err)
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]int{"accepted": len(events)}); err != nil {
		h.logger.ErrorContext(ctx, "encode response", "err", err)
	}
}

// heartbeatEventType is the liveness-ping event type that is processed for its freshness side effect at ingest and dropped rather
// than persisted as a retained event row (issue #408).
const heartbeatEventType = "snapshot_heartbeat"

// partitionHeartbeats splits a validated batch into the events to persist (everything but snapshot_heartbeat) and the freshness
// bumps to apply for the heartbeats. A heartbeat whose payload cannot be decoded or carries no PID is dropped without a bump and
// without failing the batch (the agent emits one per live snapshot PID every reconcile interval, so a malformed one is harmless).
// Preserves order and avoids allocating the toStore slice in the common no-heartbeat batch.
func partitionHeartbeats(events []api.Event) (toStore []api.Event, heartbeats []mysql.SnapshotHeartbeat) {
	// Guard the empty/nil batch explicitly: it is a no-op partition, and it lets the nil-flow analyzer (nilaway) see that `events`
	// is non-nil on every path below that slices into it, since ParseAndValidateIngestBody returns a nil slice on its error paths
	// (the caller returns before reaching here, but the analyzer does not track that status-code correlation).
	if len(events) == 0 {
		return nil, nil
	}
	firstHeartbeat := -1
	for i := range events {
		if events[i].EventType == heartbeatEventType {
			firstHeartbeat = i
			break
		}
	}
	if firstHeartbeat == -1 {
		return events, nil
	}
	// Allocate toStore eagerly only when there is a non-heartbeat prefix to carry (firstHeartbeat > 0). A batch that begins with a
	// heartbeat (including the common near-idle all-heartbeat batch) defers allocation to the first non-heartbeat append below, so
	// an all-heartbeat request allocates nothing (append to a nil slice grows on demand).
	if firstHeartbeat > 0 {
		toStore = make([]api.Event, 0, len(events)-1)
		toStore = append(toStore, events[:firstHeartbeat]...)
	}
	for i := firstHeartbeat; i < len(events); i++ {
		if events[i].EventType != heartbeatEventType {
			toStore = append(toStore, events[i])
			continue
		}
		var p struct {
			PID int `json:"pid"`
		}
		if err := json.Unmarshal(events[i].Payload, &p); err != nil || p.PID == 0 {
			continue
		}
		heartbeats = append(heartbeats, mysql.SnapshotHeartbeat{PID: p.PID, TimestampNs: events[i].TimestampNs})
	}
	return toStore, heartbeats
}

// readBodyWithCap enforces the per-request body cap in two stages and writes the appropriate error response if either
// stage rejects. Returns (body, true) on success or (nil, false) when the caller should return without further work.
// Split out of handleIngest so the latter stays under the cognitive-complexity budget (go:S3776).
//
//  1. Content-Length fast-path. If the client advertised a length beyond the cap, reject with HTTP 413 BEFORE
//     allocating any buffer. Cheap defense against a malicious or misconfigured caller that would otherwise trigger
//     a 100+ MB allocation per request.
//  2. Streaming enforce via http.MaxBytesReader. For chunked transfer-encoding (no Content-Length) or a lying
//     Content-Length, MaxBytesReader returns a typed *http.MaxBytesError once the cap is crossed mid-stream.
//     The previous shape used io.LimitReader, which silently truncates: a truncated body would then fail
//     json.Unmarshal and surface as `invalid_json`, hiding the real cause. MaxBytesReader's distinguished error is
//     what makes the 413-vs-400 split honest.
//
// When the agent sends `Content-Encoding: gzip` (#405) the MaxBytesReader cap above bounds the COMPRESSED bytes, which a
// decompression bomb can still expand past the cap; readGzipBodyWithCap therefore caps the DECOMPRESSED stream as a second,
// independent stage. The uncompressed path is kept for non-gzip callers (the demo-seed tool, any client that does not
// compress), so no agent/server version lockstep is required. HTTP 413 (RFC 9110 §15.5.14) is the canonical over-cap status;
// matches Elastic Fleet, Datadog, Splunk HEC, CrowdStrike.
func (h *Handler) readBodyWithCap(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	ctx := r.Context()
	if r.ContentLength > MaxIngestBodyBytes {
		writeErr(ctx, h.logger, w, http.StatusRequestEntityTooLarge, "body_too_large")
		return nil, false
	}
	// Cap the bytes off the wire first. For a gzip body this is the bomb's first line of defence; readGzipBodyWithCap adds
	// the decompressed cap as the second.
	r.Body = http.MaxBytesReader(w, r.Body, MaxIngestBodyBytes)

	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		return h.readGzipBodyWithCap(w, r)
	}

	body, err := io.ReadAll(r.Body)
	if err == nil {
		return body, true
	}
	return h.writeBodyReadFailure(ctx, w, err, "read_body")
}

// readGzipBodyWithCap decodes a gzip-encoded request body and enforces the per-request cap on the DECOMPRESSED bytes. The
// caller has already wrapped r.Body in a MaxBytesReader so the compressed input is bounded too; this guards the expansion a
// small compressed body can produce (a decompression bomb). A malformed gzip stream (bad header or a truncated/corrupt body)
// is reported as 400 invalid_gzip, distinct from 413 body_too_large, so the 413-vs-400 split stays honest.
func (h *Handler) readGzipBodyWithCap(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	ctx := r.Context()
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		return h.writeBodyReadFailure(ctx, w, err, "invalid_gzip")
	}
	defer func() { _ = zr.Close() }()
	// Read one byte past the cap: an exactly-at-cap decompressed body still succeeds, while an over-cap body is detected
	// without allocating the whole oversize payload.
	body, err := io.ReadAll(io.LimitReader(zr, MaxIngestBodyBytes+1))
	if err != nil {
		return h.writeBodyReadFailure(ctx, w, err, "invalid_gzip")
	}
	if len(body) > MaxIngestBodyBytes {
		writeErr(ctx, h.logger, w, http.StatusRequestEntityTooLarge, "body_too_large")
		return nil, false
	}
	return body, true
}

// writeBodyReadFailure maps a body-read error to the wire response and returns the (nil, false) the caller propagates. A
// *http.MaxBytesError (the compressed-input cap was crossed mid-stream) is 413 body_too_large regardless of encoding; any
// other error is the supplied 4xx errCode (`read_body` for a raw body, `invalid_gzip` for a malformed gzip stream).
func (h *Handler) writeBodyReadFailure(ctx context.Context, w http.ResponseWriter, err error, malformedCode string) ([]byte, bool) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeErr(ctx, h.logger, w, http.StatusRequestEntityTooLarge, "body_too_large")
		return nil, false
	}
	writeErr(ctx, h.logger, w, http.StatusBadRequest, malformedCode)
	return nil, false
}

type livezResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version,omitempty"`
	Commit        string `json:"commit,omitempty"`
	BuildTime     string `json:"build_time,omitempty"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

type readyzResponse struct {
	Status        string                 `json:"status"`
	Version       string                 `json:"version,omitempty"`
	Commit        string                 `json:"commit,omitempty"`
	BuildTime     string                 `json:"build_time,omitempty"`
	UptimeSeconds int64                  `json:"uptime_seconds"`
	Checks        map[string]checkResult `json:"checks"`
}

type checkResult struct {
	Status    string `json:"status"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (h *Handler) handleLivez(w http.ResponseWriter, r *http.Request) {
	httpserver.NoStoreJSON(r.Context(), h.logger, w, http.StatusOK, livezResponse{
		Status:        "ok",
		Version:       h.buildInfo.Version,
		Commit:        h.buildInfo.Commit,
		BuildTime:     h.buildInfo.BuildTime,
		UptimeSeconds: int64(time.Since(h.startTime).Seconds()),
	})
}

func (h *Handler) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Graceful-shutdown drain takes precedence over the DB check: once draining, report not-ready so the load balancer removes
	// this replica from rotation before the listener closes. The server keeps serving in-flight + new requests during the drain
	// window; only the readiness signal flips. Checked before the DB ping so a draining replica reports 503 even if the DB is fine.
	if h.isDraining != nil && h.isDraining() {
		httpserver.NoStoreJSON(ctx, h.logger, w, http.StatusServiceUnavailable, readyzResponse{
			Status:        "draining",
			Version:       h.buildInfo.Version,
			Commit:        h.buildInfo.Commit,
			BuildTime:     h.buildInfo.BuildTime,
			UptimeSeconds: int64(time.Since(h.startTime).Seconds()),
			Checks:        map[string]checkResult{"drain": {Status: "draining"}},
		})
		return
	}

	pingCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	checks := map[string]checkResult{}
	overall := "ok"
	httpStatus := http.StatusOK

	if h.store == nil {
		h.logger.WarnContext(ctx, "readiness check: store is not configured")
		checks["db"] = checkResult{Status: "error", Error: "unavailable"}
		overall = "degraded"
		httpStatus = http.StatusServiceUnavailable
	} else {
		start := time.Now()
		if err := h.store.PingContext(pingCtx); err != nil {
			h.logger.WarnContext(ctx, "readiness db ping failed", "err", err)
			checks["db"] = checkResult{Status: "error", Error: "unavailable"}
			overall = "degraded"
			httpStatus = http.StatusServiceUnavailable
		} else {
			checks["db"] = checkResult{Status: "ok", LatencyMS: time.Since(start).Milliseconds()}
		}
	}

	httpserver.NoStoreJSON(ctx, h.logger, w, httpStatus, readyzResponse{
		Status:        overall,
		Version:       h.buildInfo.Version,
		Commit:        h.buildInfo.Commit,
		BuildTime:     h.buildInfo.BuildTime,
		UptimeSeconds: int64(time.Since(h.startTime).Seconds()),
		Checks:        checks,
	})
}

func writeErr(ctx context.Context, logger *slog.Logger, w http.ResponseWriter, status int, code string) {
	httpserver.NoStoreJSON(ctx, logger, w, status, map[string]string{"error": code})
}
