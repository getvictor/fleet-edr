// fleet-edr-agent is the Go daemon that receives ESF and network events from system extensions over XPC, queues them in SQLite, and
// uploads them to the ingestion server. Configuration is loaded from environment variables; see agent/config for the full reference.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/net/http2"

	"github.com/fleetdm/edr/agent/coalesce"
	"github.com/fleetdm/edr/agent/codesign"
	"github.com/fleetdm/edr/agent/commander"
	"github.com/fleetdm/edr/agent/config"
	"github.com/fleetdm/edr/agent/enrich"
	"github.com/fleetdm/edr/agent/enrollment"
	"github.com/fleetdm/edr/agent/hostid"
	"github.com/fleetdm/edr/agent/metrics"
	"github.com/fleetdm/edr/agent/proctable"
	"github.com/fleetdm/edr/agent/queue"
	"github.com/fleetdm/edr/agent/receiver"
	"github.com/fleetdm/edr/agent/reconcile"
	"github.com/fleetdm/edr/agent/uploader"
	"github.com/fleetdm/edr/internal/logging"
	"github.com/fleetdm/edr/internal/observability"
)

// Build info injected via -ldflags at build time.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = ""
)

const (
	serviceName = "fleet-edr-agent"

	// uploaderMaxRetries is the per-batch retry cap before the uploader gives up
	// and falls through to the next drain tick.
	uploaderMaxRetries = 5

	// otelShutdownTimeout caps the OTel exporter flush so a dead collector cannot
	// stall agent shutdown.
	otelShutdownTimeout = 5 * time.Second

	// shutdownDrainTimeout is the window the uploader gets to flush pending
	// events after the SIGTERM/SIGINT trigger before the process exits.
	shutdownDrainTimeout = 5 * time.Second

	// agentHTTPTimeout is the per-request timeout shared by the uploader and
	// commander HTTP clients.
	agentHTTPTimeout = 30 * time.Second

	// commanderPollInterval is how often the commander polls the server for
	// pending commands. Mirrored as the package-level default in commander.New.
	commanderPollInterval = 5 * time.Second

	// h2ReadIdleTimeout / h2PingTimeout configure HTTP/2 keep-alive PINGs: if no frame arrives for ReadIdleTimeout, send a PING and
	// fail the connection if no ack lands within PingTimeout, so a half-open link (sleep, NAT rebind) is detected and re-established.
	h2ReadIdleTimeout = 15 * time.Second
	h2PingTimeout     = 10 * time.Second

	// receiverEventBuffer is the channel buffer between the XPC reader goroutine
	// and the agent's enqueue loop. 4 KiB events is one ring of slow-drain margin.
	receiverEventBuffer = 4096

	// xpcHeartbeatInterval is the cadence at which the agent sends a "hello" ping to the extension over XPC to detect a silently-dead
	// channel (issue #178). 10s + xpcHeartbeatPingTimeout = ≤15s detection window, safely under the issue's ≤30s acceptance bound.
	xpcHeartbeatInterval = 10 * time.Second
	// xpcHeartbeatPingTimeout is how long the agent waits for a "hello-ack" per heartbeat. 5s matches HELLO_ACK_TIMEOUT_NS in
	// xpc_bridge.c and is comfortably above the observed round-trip latency (1-3 ms on edr-dev).
	xpcHeartbeatPingTimeout = 5 * time.Second
)

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

	shutdownOTel, err := observability.Init(ctx, observability.OptionsFromEnv(observability.Options{
		ServiceName:    serviceName,
		ServiceVersion: version,
	}))
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

	// Proactively refresh the host token before it expires so a live agent never lapses (self-validating tokens have a bounded TTL).
	// Optional capability: only the concrete provider implements Refresher; test doubles skip it.
	if refresher, ok := tokenProvider.(enrollment.Refresher); ok {
		go refresher.RunRefresh(ctx)
	}

	q, err := queue.Open(ctx, cfg.QueueDBPath, queue.Options{MaxBytes: config.DefaultQueueMaxBytes, Logger: logger})
	if err != nil {
		logger.ErrorContext(ctx, "open queue", "err", err)
		return err
	}
	defer func() { _ = q.Close() }()
	// The Recorder is the single OTel write surface; the queue uses it for QueueDropped, the uploader uses it for
	// EventsDroppedTooLarge, and the queue-depth observable gauge reads q.Depth() on every collection cycle. metrics.New
	// returns a no-op-safe Recorder when OTEL_EXPORTER_OTLP_ENDPOINT is unset.
	rec := metrics.New(q)
	q.SetMetrics(rec)

	agentTransport, httpClient, err := newAgentHTTPClient(cfg, logger)
	if err != nil {
		return err
	}

	up := uploader.New(q, uploader.Config{
		ServerURL:  cfg.ServerURL,
		TokenFn:    tokenProvider.Token,
		OnAuthFail: tokenProvider.OnUnauthorized,
		BatchSize:  config.DefaultBatchSize,
		Interval:   config.DefaultUploadInterval,
		MaxRetries: uploaderMaxRetries,
	}, httpClient, logger)
	up.SetMetrics(rec)

	// esfDispatcher bridges the commander (which wants a stable ApplicationControlSender across receiver reconnects) and the ESF
	// receiver loop (which builds a fresh *receiver.Receiver on every connect). The loop's OnConnected hook publishes into the
	// dispatcher; OnDisconnected clears it so commands issued during a reconnect window fail fast.
	esfDispatcher := receiver.NewDispatcher()

	// coalescer collapses repetitive network_connect / dns_query telemetry within a window before enqueue (issue #408). A zero
	// window disables it (Handle is a direct passthrough, Run just waits on ctx), so it can be wired unconditionally.
	coalescer := coalesce.New(config.DefaultNetworkCoalesceWindow, q.Enqueue, logger)
	go coalescer.Run(ctx)

	pidTable := proctable.New()
	go startReceiverLoop(ctx, receiverLoopParams{
		logger:      logger,
		xpcService:  cfg.XPCService,
		enqueue:     coalescer.Handle,
		pt:          pidTable,
		updateTable: true,
		dispatcher:  esfDispatcher,
	})
	if cfg.NetXPCService != "" {
		go startReceiverLoop(ctx, receiverLoopParams{
			logger:       logger,
			xpcService:   cfg.NetXPCService,
			enqueue:      coalescer.Handle,
			pt:           pidTable,
			upgradeProbe: func() bool { return receiver.NEUpgradePending(ctx) },
		})
	}
	go runUploader(ctx, up, logger)

	startCommander(ctx, hostID, cfg.ServerURL, tokenProvider, esfDispatcher, agentTransport, logger)
	go pruneLoop(ctx, q, config.DefaultPruneAge, logger)
	startProcessReconciler(ctx, cfg, pidTable, q, tokenProvider, logger)

	<-ctx.Done()
	// Drain buffered network/DNS representatives into the queue before the uploader drains the queue and the queue closes, so a
	// clean shutdown loses no coalesced telemetry. No-op when coalescing is disabled.
	coalescer.Flush(context.WithoutCancel(ctx))
	drainAndReport(up, q, logger)
	return nil
}

// flushOTel caps the OTel flush at otelShutdownTimeout so a dead collector
// doesn't stall the shutdown path.
func flushOTel(shutdown func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		slog.Default().WarnContext(ctx, "otel shutdown", "err", err)
	}
}

// deriveHostID returns the host identity the agent advertises. An operator override (EDR_HOST_ID) wins; otherwise we read
// IOPlatformUUID. Failures here are non-fatal: the enrollment step re-derives and fails loudly if needed.
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
// dial/idle timeouts. Real deployments behind HTTPS_PROXY fail without them.
func newAgentHTTPClient(cfg *config.Config, logger *slog.Logger) (http.RoundTripper, *http.Client, error) {
	tlsCfg, err := enrollment.BuildTLSConfig(cfg.AllowInsecure, cfg.ServerFingerprint, logger)
	if err != nil {
		logger.ErrorContext(context.Background(), "build tls config", "err", err)
		return nil, nil, err
	}
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.TLSClientConfig = tlsCfg
	// Enable HTTP/2 with keep-alive PINGs so the long-lived agent connection (shared by the uploader + commander) detects a half-open
	// link (laptop sleep, NAT rebind) and re-establishes it instead of hanging until the request timeout. ConfigureTransports negotiates
	// h2 over the existing TLS config and returns the h2 transport for tuning. Non-fatal on failure: the agent keeps HTTP/1.1 keep-alive.
	if h2, h2err := http2.ConfigureTransports(baseTransport); h2err == nil {
		h2.ReadIdleTimeout = h2ReadIdleTimeout
		h2.PingTimeout = h2PingTimeout
	} else {
		logger.WarnContext(context.Background(), "http2 configure failed; using http/1.1 keep-alive", "err", h2err)
	}
	agentTransport := otelhttp.NewTransport(baseTransport)
	return agentTransport, &http.Client{Transport: agentTransport, Timeout: agentHTTPTimeout}, nil
}

// runUploader owns the uploader goroutine; any non-shutdown-induced exit is logged as an error so SigNoz alerts fire if the uploader
// dies while the agent is otherwise healthy.
func runUploader(ctx context.Context, up *uploader.Uploader, logger *slog.Logger) {
	if err := up.Run(ctx); err != nil && ctx.Err() == nil {
		logger.ErrorContext(ctx, "uploader", "err", err)
	}
}

// drainAndReport gives the uploader a shutdownDrainTimeout window to flush pending events after the shutdown signal, then logs the
// final queue depth so post-mortems can tell "clean drain" from "we hard-stopped with N events queued".
func drainAndReport(up *uploader.Uploader, q *queue.Queue, logger *slog.Logger) {
	shutdownCtx := context.Background()
	logger.InfoContext(shutdownCtx, "agent shutting down")

	drainCtx, drainCancel := context.WithTimeout(shutdownCtx, shutdownDrainTimeout)
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

// startCommander spins up the command-poll loop when we have a host_id. With no host_id the agent keeps running (events still upload)
// but cannot receive commands, so commander launch is skipped and logged.
func startCommander(
	ctx context.Context,
	hostID, serverURL string,
	tokenProvider enrollment.TokenProvider,
	appControlSender commander.ApplicationControlSender,
	transport http.RoundTripper,
	logger *slog.Logger,
) {
	if hostID == "" {
		logger.WarnContext(ctx, "no host_id available; commander disabled")
		return
	}
	cmdr := commander.New(commander.Config{
		ServerURL:                serverURL,
		TokenFn:                  tokenProvider.Token,
		OnAuthFail:               tokenProvider.OnUnauthorized,
		HostID:                   hostID,
		Interval:                 commanderPollInterval,
		ApplicationControlSender: appControlSender,
	}, &http.Client{Transport: transport, Timeout: 10 * time.Second}, logger)
	go func() {
		if err := cmdr.Run(ctx); err != nil && ctx.Err() == nil {
			logger.ErrorContext(ctx, "commander", "err", err)
		}
	}()
	logger.InfoContext(ctx, "commander polling", "host_id_prefix", safePrefix(hostID))
}

// startProcessReconciler runs the agent-side kill(pid,0) sweep that closes processes whose kernel exit notification went missing
// (issue #6 client half). Disabled when EDR_PROCESS_RECONCILE_INTERVAL=0.
func startProcessReconciler(
	ctx context.Context,
	cfg *config.Config,
	pt *proctable.Table,
	q *queue.Queue,
	tokenProvider enrollment.TokenProvider,
	logger *slog.Logger,
) {
	if cfg.ProcessReconcileInterval == 0 {
		logger.InfoContext(ctx, "process reconciliation disabled",
			"edr.reconcile.interval_seconds", 0)
		return
	}
	r := reconcile.New(pt, q, tokenProvider.HostID, reconcile.Options{
		Interval: cfg.ProcessReconcileInterval,
		Logger:   logger,
	})
	go r.Run(ctx)
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

// startReceiverLoop builds the per-service receiver.Loop and runs it. The Loop owns the connect / reconnect / backoff / heartbeat
// machinery; this function only wires the agent's enqueue sink + proctable into OnEvent and (for the ESF service) the
// application_control Dispatcher into OnConnected / OnDisconnected. dispatcher may be nil for non-ESF services that do not receive
// outbound pushes. enqueue is the coalescer's Handle: network_connect / dns_query are coalesced before reaching the queue, every
// other event passes straight through.
// receiverLoopParams configures startReceiverLoop. ctx is passed separately so the call sites read like a normal context-first
// function; everything else is grouped here. dispatcher may be nil for non-ESF services that do not receive outbound pushes.
type receiverLoopParams struct {
	logger       *slog.Logger
	xpcService   string
	enqueue      func(context.Context, []byte) error
	pt           *proctable.Table
	updateTable  bool
	dispatcher   *receiver.Dispatcher
	upgradeProbe func() bool
}

func startReceiverLoop(ctx context.Context, p receiverLoopParams) {
	factory := func() receiver.Connector {
		return receiver.New(p.xpcService, receiverEventBuffer)
	}
	hooks := receiver.LoopHooks{
		OnEvent: func(ctx context.Context, evt receiver.Event) {
			// Fill a btm_launch_item_add event's executable_code_signing from the on-disk signing of the registered
			// executable: the sandboxed extension cannot read it on a SIP-enabled host, so the agent (unsandboxed root,
			// off the ES callback thread) computes it here. No-op for every other event and on the linux headless build.
			data := enrich.BtmExecutableSigning(evt.Data, codesign.Evaluate)
			if p.updateTable {
				updateProcTable(p.pt, data)
			}
			if err := p.enqueue(ctx, data); err != nil {
				p.logger.WarnContext(ctx, "enqueue", "err", err)
			}
		},
	}
	if p.dispatcher != nil {
		hooks.OnConnected = p.dispatcher.Set
		hooks.OnDisconnected = p.dispatcher.Clear
	}
	// Only the network-extension loop wires UpgradeProbe (nil for ESF): after a staged upgrade the NE's nesessionmanager-owned
	// Mach service stays bound to the terminated old version until reboot, so a sustained NE connect failure paired with a
	// pending-uninstall old version means "reboot required", not "needs approval" (#399).
	hooks.UpgradeProbe = p.upgradeProbe
	loop := receiver.NewLoop(factory, receiver.LoopConfig{
		ServiceName:       p.xpcService,
		HeartbeatInterval: xpcHeartbeatInterval,
		HeartbeatTimeout:  xpcHeartbeatPingTimeout,
	}, hooks, p.logger)
	loop.Run(ctx)
}

// eventHeader is a minimal struct for peeking at event_type, pid, path, and uid.
type eventHeader struct {
	EventType   string          `json:"event_type"`
	TimestampNs int64           `json:"timestamp_ns"`
	Payload     json.RawMessage `json:"payload"`
}

type execFields struct {
	PID      int32  `json:"pid"`
	Path     string `json:"path"`
	UID      uint32 `json:"uid"`
	Snapshot bool   `json:"snapshot"`
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
			Path:       fields.Path,
			UID:        fields.UID,
			StartTime:  hdr.TimestampNs,
			IsSnapshot: fields.Snapshot,
		})
	case "exit":
		var fields exitFields
		if err := json.Unmarshal(hdr.Payload, &fields); err != nil {
			return
		}
		pt.Remove(fields.PID)
	}
}
