//go:build !darwin || !cgo

package headless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/fleetdm/edr/agent/queue"
	"github.com/fleetdm/edr/agent/receiver"
)

const (
	// maxEventBytes caps the size of a single POST /event body. The production wire envelope is well under 64 KiB; the cap keeps a
	// runaway test scenario from exhausting memory in the control plane handler.
	maxEventBytes = 1 << 20 // 1 MiB

	// controlReadTimeout, controlWriteTimeout, controlShutdownTimeout are deliberately short. The control plane is local-only
	// (unix socket); slow clients indicate a test bug, not a real network condition.
	controlReadTimeout     = 5 * time.Second
	controlWriteTimeout    = 5 * time.Second
	controlShutdownTimeout = 2 * time.Second

	// queueDepthTimeout caps a single q.Depth call from blocking GET /state. The HTTP write timeout is the outer safety net but only
	// fires after the response starts streaming; an explicit per-call timeout bounds the DB query itself.
	queueDepthTimeout = 500 * time.Millisecond

	// controlSocketMode locks the unix socket to the running user only. The headless binary is single-user dev/test tooling; a more
	// permissive mode would let any process on the host inject events.
	controlSocketMode os.FileMode = 0o600

	// HTTP header names + content types centralised so Sonar's S1192 (duplicated literal) doesn't trip across the three
	// inject + state + error response paths. None of these are wire contracts that vary per call site.
	contentTypeHeader = "Content-Type"
	contentTypeJSON   = "application/json"
)

// startControlPlane binds a unix socket at socketPath and serves the control-plane HTTP API on it. Returns a shutdown function the
// caller defers; the function stops the HTTP server (5s grace) and removes the socket file.
func startControlPlane(
	ctx context.Context, socketPath string, recv *receiver.Receiver, q *queue.Queue, cnt *counters, logger *slog.Logger,
) (func(), error) {
	// Remove a stale socket from a previous run; net.Listen would otherwise error with "address already in use". Guard with Lstat to
	// refuse to delete a non-socket path so a misconfigured --control-socket pointed at a regular file does not nuke that file.
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to remove non-socket %s; pass a fresh path", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("remove stale socket %s: %w", socketPath, err)
		}
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, controlSocketMode); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("chmod %s: %w", socketPath, err)
	}

	mux := http.NewServeMux()
	mux.Handle("POST /event", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlePostEvent(w, r, recv, cnt, logger)
	}))
	mux.Handle("GET /state", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleGetState(w, r, q, cnt, logger)
	}))

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  controlReadTimeout,
		WriteTimeout: controlWriteTimeout,
	}

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- srv.Serve(listener) }()
	logger.InfoContext(ctx, "control plane listening", "socket", socketPath)

	// The shutdown closure is idempotent via sync.Once. Run calls it explicitly between ctx.Done() and drainOnShutdown so the
	// control plane stops accepting new POSTs before the final drain, and ALSO defers it as a safety net for early-return paths
	// (e.g. an unexpected error after this function succeeds). Without Once, the second invocation would block forever waiting
	// for a serveErrCh that the first invocation already consumed.
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), controlShutdownTimeout)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				logger.WarnContext(shutdownCtx, "control plane shutdown", "err", err)
			}
			_ = os.Remove(socketPath)
			// Drain the serve goroutine so it doesn't outlive the shutdown call.
			if err := <-serveErrCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.WarnContext(shutdownCtx, "control plane serve", "err", err)
			}
		})
	}
	return shutdown, nil
}

// handlePostEvent reads a single event-envelope JSON body from the request and injects it into the receiver. The body is forwarded
// verbatim; the control plane does not parse or validate the envelope (that is the server's job). On a successful inject, returns 202
// with a JSON ack carrying the running events_injected count so the test scenario driver can use it as a happens-before signal.
func handlePostEvent(
	w http.ResponseWriter, r *http.Request, recv *receiver.Receiver, cnt *counters, logger *slog.Logger,
) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEventBytes))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if len(body) == 0 {
		writeJSONError(w, http.StatusBadRequest, "empty event body")
		return
	}
	if !json.Valid(body) {
		writeJSONError(w, http.StatusBadRequest, "body is not valid JSON")
		return
	}
	if err := recv.Inject(body); err != nil {
		cnt.injectErrors.Add(1)
		// ErrBufferFull is the test-visible failure: the scenario is feeding events faster than the queue can drain. A 503 lets the
		// driver back off rather than mistaking the failure for a malformed-payload bug.
		status := http.StatusServiceUnavailable
		if !errors.Is(err, receiver.ErrBufferFull) {
			status = http.StatusInternalServerError
		}
		writeJSONError(w, status, "inject: "+err.Error())
		return
	}
	n := cnt.eventsInjected.Add(1)
	cnt.lastInjectAtUnix.Store(time.Now().Unix())
	logger.DebugContext(r.Context(), "control plane injected event", "events_injected", n)
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"events_injected": n})
}

// stateResponse is the JSON body of GET /state. Field names are snake_case to match the rest of the agent / server wire format.
type stateResponse struct {
	EventsInjected   int64 `json:"events_injected"`
	InjectErrors     int64 `json:"inject_errors"`
	LastInjectAtUnix int64 `json:"last_inject_at_unix"`
	QueueDepth       int64 `json:"queue_depth"`
}

// handleGetState reports control-plane and queue observability state. Queue depth runs under an explicit short timeout so a stuck DB
// query cannot block the response past queueDepthTimeout; -1 is reported on timeout / error so the in-memory counters still surface.
func handleGetState(
	w http.ResponseWriter, r *http.Request, q *queue.Queue, cnt *counters, logger *slog.Logger,
) {
	depthCtx, cancel := context.WithTimeout(r.Context(), queueDepthTimeout)
	defer cancel()
	depth, err := q.Depth(depthCtx)
	if err != nil {
		logger.WarnContext(r.Context(), "queue depth", "err", err)
		// Report -1 instead of failing the whole call: the in-memory counters are still useful and the client can decide what to do.
		depth = -1
	}
	resp := stateResponse{
		EventsInjected:   cnt.eventsInjected.Load(),
		InjectErrors:     cnt.injectErrors.Load(),
		LastInjectAtUnix: cnt.lastInjectAtUnix.Load(),
		QueueDepth:       depth,
	}
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	_ = json.NewEncoder(w).Encode(resp)
}

// writeJSONError emits a small JSON error body so a client parsing the response can read .error without sniffing the body type.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set(contentTypeHeader, contentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
