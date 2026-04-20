// fleet-edr-agent is the Go daemon that receives ESF and network events from
// system extensions over XPC, queues them in SQLite, and uploads them to the
// ingestion server. Configuration is loaded from environment variables; see
// agent/config for the full reference.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/fleetdm/edr/agent/commander"
	"github.com/fleetdm/edr/agent/config"
	"github.com/fleetdm/edr/agent/enrollment"
	"github.com/fleetdm/edr/agent/hostid"
	"github.com/fleetdm/edr/agent/logging"
	"github.com/fleetdm/edr/agent/metrics"
	"github.com/fleetdm/edr/agent/observability"
	"github.com/fleetdm/edr/agent/proctable"
	"github.com/fleetdm/edr/agent/queue"
	"github.com/fleetdm/edr/agent/receiver"
	"github.com/fleetdm/edr/agent/uploader"
)

// Build info injected via -ldflags at build time.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = ""
)

const serviceName = "fleet-edr-agent"

func main() {
	if err := run(); err != nil {
		_, _ = os.Stderr.WriteString("fatal: " + err.Error() + "\n")
		os.Exit(2)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	shutdownOTel, err := observability.Init(ctx, observability.Options{
		ServiceName:    serviceName,
		ServiceVersion: version,
	})
	if err != nil {
		return err
	}
	// Defer shutdown as soon as Init succeeds so any later startup failure (logging.New,
	// queue.Open, etc.) still flushes buffered OTel telemetry on its way out.
	defer flushOTel(shutdownOTel)

	hostID := deriveHostID(ctx, cfg.HostIDOverride)
	logger, err := newAgentLogger(cfg, hostID)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	receiver.SetLogger(logger)

	logAgentStart(ctx, logger, cfg)

	tokenProvider, err := enrollment.Ensure(ctx, enrollment.Options{
		ServerURL:         cfg.ServerURL,
		EnrollSecret:      cfg.EnrollSecret,
		TokenFile:         cfg.TokenFile,
		ServerFingerprint: cfg.ServerFingerprint,
		AllowInsecure:     cfg.AllowInsecure,
		HostIDOverride:    cfg.HostIDOverride,
		AgentVersion:      version,
		Logger:            logger,
	})
	if err != nil {
		logger.ErrorContext(ctx, "enrollment", "err", err)
		return err
	}
	// The TokenProvider owns the current host_id (enrolled value, not necessarily the same
	// as the pre-enroll derived value above). Keep hostID in sync for the commander.
	if tpID := tokenProvider.HostID(); tpID != "" {
		hostID = tpID
	}

	q, err := queue.Open(ctx, cfg.QueueDBPath, queue.Options{MaxBytes: cfg.QueueMaxBytes, Logger: logger})
	if err != nil {
		logger.ErrorContext(ctx, "open queue", "err", err)
		return err
	}
	defer func() { _ = q.Close() }()
	q.SetMetrics(metrics.New())

	agentTransport, httpClient, err := newAgentHTTPClient(cfg, logger)
	if err != nil {
		return err
	}

	up := uploader.New(q, uploader.Config{
		ServerURL:  cfg.ServerURL,
		TokenFn:    tokenProvider.Token,
		OnAuthFail: tokenProvider.OnUnauthorized,
		BatchSize:  cfg.BatchSize,
		Interval:   cfg.UploadInterval,
		MaxRetries: 5,
	}, httpClient, logger)

	// policyDispatcher bridges the commander (which wants a stable PolicySender across
	// receiver reconnects) and runReceiverLoop (which creates a new *receiver.Receiver on
	// every connect). The ESF receiver loop publishes into this dispatcher on connect and
	// clears it on disconnect.
	esfPolicyDispatcher := &policyDispatcher{}

	pidTable := proctable.New()
	go runReceiverLoop(ctx, logger, cfg.XPCService, q, pidTable, true, esfPolicyDispatcher)
	if cfg.NetXPCService != "" {
		go runReceiverLoop(ctx, logger, cfg.NetXPCService, q, pidTable, false, nil)
	}
	go runUploader(ctx, up, logger)

	startCommander(ctx, hostID, cfg.ServerURL, tokenProvider, esfPolicyDispatcher, agentTransport, logger)
	go pruneLoop(ctx, q, cfg.PruneAge, logger)

	<-ctx.Done()
	drainAndReport(up, q, logger)
	return nil
}

// flushOTel caps the OTel flush at 5s so a dead collector doesn't stall the
// shutdown path.
func flushOTel(shutdown func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		slog.Default().WarnContext(ctx, "otel shutdown", "err", err)
	}
}

// deriveHostID returns the host identity the agent advertises. An operator
// override (EDR_HOST_ID) wins; otherwise we read IOPlatformUUID. Failures here
// are non-fatal — the enrollment step re-derives and fails loudly if needed.
func deriveHostID(ctx context.Context, override string) string {
	if override != "" {
		return override
	}
	if derived, err := hostid.Get(ctx); err == nil {
		return derived
	}
	return ""
}

// newAgentLogger builds the base slog.Logger, pre-stamping host_id onto every
// record so log search in SigNoz is routinely scoped to one endpoint.
func newAgentLogger(cfg *config.Config, hostID string) (*slog.Logger, error) {
	return logging.New(os.Stderr, logging.Options{
		Level:               cfg.LogLevel,
		Format:              cfg.LogFormat,
		InstrumentationName: serviceName,
		BaseAttrs:           []slog.Attr{slog.String("host_id", hostID)},
	})
}

// logAgentStart emits the startup banner + the insecure-HTTP warning when
// applicable. Factored out of run() so complexity stays under the linter cap.
func logAgentStart(ctx context.Context, logger *slog.Logger, cfg *config.Config) {
	logger.InfoContext(ctx, "fleet-edr-agent starting",
		"version", version,
		"commit", commit,
		"build_time", buildTime,
		"server_url", cfg.ServerURL,
		"insecure", cfg.AllowInsecure,
	)
	if cfg.AllowInsecure {
		logger.WarnContext(ctx, "EDR_ALLOW_INSECURE=1 is set; use https:// in production")
	}
}

// newAgentHTTPClient wires one TLS config into every agent HTTP client so the
// self-signed / fingerprint-pinned policies that worked during enroll also
// apply to the uploader and commander. Without this, every post-enroll request
// would fail "certificate signed by unknown authority" because
// http.DefaultTransport uses the system trust store with no knowledge of
// EDR_ALLOW_INSECURE or EDR_SERVER_FINGERPRINT.
//
// We clone http.DefaultTransport (rather than &http.Transport{}) so the agent
// keeps ProxyFromEnvironment, keep-alive, and the stdlib's hardened
// dial/idle timeouts — real deployments behind HTTPS_PROXY fail without them.
func newAgentHTTPClient(cfg *config.Config, logger *slog.Logger) (http.RoundTripper, *http.Client, error) {
	tlsCfg, err := enrollment.BuildTLSConfig(cfg.AllowInsecure, cfg.ServerFingerprint, logger)
	if err != nil {
		logger.ErrorContext(context.Background(), "build tls config", "err", err)
		return nil, nil, err
	}
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.TLSClientConfig = tlsCfg
	agentTransport := otelhttp.NewTransport(baseTransport)
	return agentTransport, &http.Client{Transport: agentTransport, Timeout: 30 * time.Second}, nil
}

// runUploader owns the uploader goroutine; any non-shutdown-induced exit is
// logged as an error so SigNoz alerts fire if the uploader dies while the
// agent is otherwise healthy.
func runUploader(ctx context.Context, up *uploader.Uploader, logger *slog.Logger) {
	if err := up.Run(ctx); err != nil && ctx.Err() == nil {
		logger.ErrorContext(ctx, "uploader", "err", err)
	}
}

// drainAndReport gives the uploader a 5s window to flush pending events after
// the shutdown signal, then logs the final queue depth so post-mortems can
// tell "clean drain" from "we hard-stopped with N events queued".
func drainAndReport(up *uploader.Uploader, q *queue.Queue, logger *slog.Logger) {
	shutdownCtx := context.Background()
	logger.InfoContext(shutdownCtx, "agent shutting down")

	drainCtx, drainCancel := context.WithTimeout(shutdownCtx, 5*time.Second)
	defer drainCancel()
	if err := up.Drain(drainCtx); err != nil {
		logger.WarnContext(drainCtx, "uploader drain", "err", err)
	}

	depth, _ := q.Depth(shutdownCtx)
	logger.InfoContext(shutdownCtx, "shutdown queue depth", "depth", depth)
}

func safePrefix(s string) string {
	if len(s) < 8 {
		return s
	}
	return s[:8]
}

// startCommander spins up the command-poll loop when we have a host_id. With no
// host_id the agent keeps running (events still upload) but cannot receive commands,
// so commander launch is skipped and logged.
func startCommander(
	ctx context.Context,
	hostID, serverURL string,
	tokenProvider enrollment.TokenProvider,
	policySender commander.PolicySender,
	transport http.RoundTripper,
	logger *slog.Logger,
) {
	if hostID == "" {
		logger.WarnContext(ctx, "no host_id available; commander disabled")
		return
	}
	cmdr := commander.New(commander.Config{
		ServerURL:    serverURL,
		TokenFn:      tokenProvider.Token,
		OnAuthFail:   tokenProvider.OnUnauthorized,
		HostID:       hostID,
		Interval:     5 * time.Second,
		PolicySender: policySender,
	}, &http.Client{Transport: transport, Timeout: 10 * time.Second}, logger)
	go func() {
		if err := cmdr.Run(ctx); err != nil && ctx.Err() == nil {
			logger.ErrorContext(ctx, "commander", "err", err)
		}
	}()
	logger.InfoContext(ctx, "commander polling", "host_id_prefix", safePrefix(hostID))
}

// pruneLoop periodically prunes uploaded events older than pruneAge from the
// persistent queue.
func pruneLoop(ctx context.Context, q *queue.Queue, pruneAge time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pruned, err := q.Prune(ctx, pruneAge)
			switch {
			case err != nil:
				logger.WarnContext(ctx, "prune", "err", err)
			case pruned > 0:
				logger.InfoContext(ctx, "pruned old events", "count", pruned)
			}
		}
	}
}

// runReceiverLoop connects to an XPC service and reconnects with exponential backoff.
// If dispatcher is non-nil, every successful connection publishes the current *Receiver
// into it so outbound callers (commander set_blocklist) can send messages to the peer;
// disconnects clear the dispatcher to prevent sending on a dead handle.
func runReceiverLoop(
	ctx context.Context,
	logger *slog.Logger,
	xpcService string,
	q *queue.Queue,
	pt *proctable.Table,
	updateTable bool,
	dispatcher *policyDispatcher,
) {
	const (
		initialBackoff = time.Second
		maxBackoff     = 30 * time.Second
	)

	backoff := initialBackoff
	for ctx.Err() == nil {
		reconnect, connected := runReceiverOnce(ctx, logger, xpcService, q, pt, updateTable, dispatcher)
		if connected {
			// Successful session; reset the backoff so the next reconnect is fast.
			backoff = initialBackoff
		}
		if !reconnect {
			return
		}
		retryIn := initialBackoff
		if !connected {
			// Connection never established — back off exponentially before
			// retrying to avoid a tight reconnect loop against a dead peer.
			retryIn = backoff
			backoff = min(backoff*2, maxBackoff)
		} else {
			logger.InfoContext(ctx, "receiver reconnecting", "service", xpcService, "retry_in", retryIn)
		}
		if !sleepCtx(ctx, retryIn) {
			return
		}
	}
}

// runReceiverOnce performs a single connect→pipe→disconnect cycle against the
// XPC service. Returns (reconnect, connected): reconnect says whether the outer
// backoff loop should try again, and connected tells the caller whether the
// last attempt actually established the peer link so the backoff can be reset.
func runReceiverOnce(
	ctx context.Context,
	logger *slog.Logger,
	xpcService string,
	q *queue.Queue,
	pt *proctable.Table,
	updateTable bool,
	dispatcher *policyDispatcher,
) (reconnect, connected bool) {
	recv := receiver.New(xpcService, 4096)
	if err := recv.Connect(); err != nil {
		logger.WarnContext(ctx, "receiver connect", "service", xpcService, "err", err)
		return true, false
	}
	logger.InfoContext(ctx, "receiver connected", "service", xpcService)

	if dispatcher != nil {
		dispatcher.set(recv)
	}
	reconnect = pipeEvents(ctx, logger, recv, q, pt, updateTable)
	if dispatcher != nil {
		dispatcher.clear()
	}
	recv.Disconnect()
	return reconnect, true
}

// pipeEvents reads from the receiver and enqueues events until ctx is cancelled or XPC errors.
func pipeEvents(ctx context.Context, logger *slog.Logger, recv *receiver.Receiver, q *queue.Queue, pt *proctable.Table, updateTable bool) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		case evt := <-recv.Events():
			if updateTable {
				updateProcTable(pt, evt.Data)
			}
			if err := q.Enqueue(ctx, evt.Data); err != nil {
				logger.WarnContext(ctx, "enqueue", "err", err)
			}
		case errCode := <-recv.Errors():
			// All XPC error codes force a reconnect today; the switch is kept so the
			// call site is explicit about which codes are expected vs unexpected and so
			// we can route them differently later (e.g. backoff vs fail-fast).
			logger.WarnContext(ctx, "xpc error", "code", errCode,
				"expected", errCode == receiver.ErrorConnectionInvalid ||
					errCode == receiver.ErrorConnectionInterrupted ||
					errCode == receiver.ErrorTerminated)
			return true
		}
	}
}

// eventHeader is a minimal struct for peeking at event_type, pid, path, and uid.
type eventHeader struct {
	EventType   string          `json:"event_type"`
	TimestampNs int64           `json:"timestamp_ns"`
	Payload     json.RawMessage `json:"payload"`
}

type execFields struct {
	PID  int32  `json:"pid"`
	Path string `json:"path"`
	UID  uint32 `json:"uid"`
}

type exitFields struct {
	PID int32 `json:"pid"`
}

func updateProcTable(pt *proctable.Table, data []byte) {
	var hdr eventHeader
	if err := json.Unmarshal(data, &hdr); err != nil {
		return
	}

	switch hdr.EventType {
	case "exec":
		var fields execFields
		if err := json.Unmarshal(hdr.Payload, &fields); err != nil {
			return
		}
		pt.Update(fields.PID, proctable.ProcessInfo{
			Path:      fields.Path,
			UID:       fields.UID,
			StartTime: hdr.TimestampNs,
		})
	case "exit":
		var fields exitFields
		if err := json.Unmarshal(hdr.Payload, &fields); err != nil {
			return
		}
		pt.Remove(fields.PID)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// policyDispatcher satisfies commander.PolicySender across the lifecycle of the ESF
// receiver: runReceiverLoop publishes the current *Receiver on connect and clears it on
// disconnect. Between clear() and the next set(), SendPolicy returns an error so the
// command gets reported as `failed` and the server's next PUT policy fan-out re-queues
// the update. Using atomic.Pointer keeps the hot path (SendPolicy from commander) lock-free.
type policyDispatcher struct {
	cur atomic.Pointer[receiver.Receiver]
}

func (d *policyDispatcher) set(r *receiver.Receiver) { d.cur.Store(r) }

// clear unconditionally clears the published receiver pointer. This is safe under the
// current runReceiverLoop lifecycle, which serialises set/clear for a single service —
// there is only one goroutine calling set() and clear() in sequence per connect cycle,
// so there is no window where a later set() can be wiped by an earlier clear(). If this
// dispatcher is ever extended to handle overlapping receiver lifecycles (multiple
// services or concurrent reconnects), clear() would need receiver-aware CompareAndSwap
// semantics to avoid nulling out a freshly-published pointer from a later set().
func (d *policyDispatcher) clear() {
	d.cur.Store(nil)
}

func (d *policyDispatcher) SendPolicy(payload []byte) error {
	r := d.cur.Load()
	if r == nil {
		return fmt.Errorf("policy dispatcher: no receiver connected")
	}
	return r.SendPolicy(payload)
}
