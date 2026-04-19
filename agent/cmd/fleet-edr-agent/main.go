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
	defer func() {
		otelCtx, otelCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer otelCancel()
		if err := shutdownOTel(otelCtx); err != nil {
			slog.Default().WarnContext(otelCtx, "otel shutdown", "err", err)
		}
	}()

	// Derive host_id early so the base logger carries it before we start touching other
	// subsystems. The enrollment.Ensure step below re-derives for the enroll payload but
	// uses the same source.
	hostID := cfg.HostIDOverride
	if hostID == "" {
		if derived, derivErr := hostid.Get(ctx); derivErr == nil {
			hostID = derived
		}
	}

	baseAttrs := []slog.Attr{slog.String("host_id", hostID)}
	logger, err := logging.New(os.Stderr, logging.Options{
		Level:               cfg.LogLevel,
		Format:              cfg.LogFormat,
		InstrumentationName: serviceName,
		BaseAttrs:           baseAttrs,
	})
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	receiver.SetLogger(logger)

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

	// Enroll (or load the persisted token) before touching the queue / uploader. A failure
	// here is fatal — the agent has no way to upload events without a valid token.
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

	pidTable := proctable.New()

	// Build one TLS config for every agent HTTP client so the self-signed /
	// fingerprint-pinned policies that worked during enroll also apply to the uploader
	// and commander. Without this, every post-enroll request fails with "certificate
	// signed by unknown authority" because DefaultTransport uses the system trust store
	// with no knowledge of EDR_ALLOW_INSECURE or EDR_SERVER_FINGERPRINT.
	//
	// We clone http.DefaultTransport (rather than &http.Transport{}) so the agent keeps
	// ProxyFromEnvironment, keep-alive, and the stdlib's hardened dial/idle timeouts —
	// real deployments behind HTTPS_PROXY fail without them.
	tlsCfg, err := enrollment.BuildTLSConfig(cfg.AllowInsecure, cfg.ServerFingerprint, logger)
	if err != nil {
		logger.ErrorContext(ctx, "build tls config", "err", err)
		return err
	}
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.TLSClientConfig = tlsCfg
	agentTransport := otelhttp.NewTransport(baseTransport)

	httpClient := &http.Client{
		Transport: agentTransport,
		Timeout:   30 * time.Second,
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

	// Start ESF and network receiver loops.
	go runReceiverLoop(ctx, logger, cfg.XPCService, q, pidTable, true, esfPolicyDispatcher)
	if cfg.NetXPCService != "" {
		go runReceiverLoop(ctx, logger, cfg.NetXPCService, q, pidTable, false, nil)
	}

	go func() {
		if err := up.Run(ctx); err != nil && ctx.Err() == nil {
			logger.ErrorContext(ctx, "uploader", "err", err)
		}
	}()

	startCommander(ctx, hostID, cfg.ServerURL, tokenProvider, esfPolicyDispatcher, agentTransport, logger)
	go pruneLoop(ctx, q, cfg.PruneAge, logger)

	<-ctx.Done()
	logger.InfoContext(context.Background(), "agent shutting down")

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := up.Drain(drainCtx); err != nil {
		logger.WarnContext(drainCtx, "uploader drain", "err", err)
	}
	drainCancel()

	depth, _ := q.Depth(context.Background())
	logger.InfoContext(context.Background(), "shutdown queue depth", "depth", depth)

	// OTel shutdown is handled by the deferred flusher installed right after observability.Init.
	return nil
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
	for {
		if ctx.Err() != nil {
			return
		}

		recv := receiver.New(xpcService, 4096)

		if err := recv.Connect(); err != nil {
			logger.WarnContext(ctx, "receiver connect", "service", xpcService, "err", err, "retry_in", backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		logger.InfoContext(ctx, "receiver connected", "service", xpcService)
		backoff = initialBackoff
		if dispatcher != nil {
			dispatcher.set(recv)
		}

		reconnect := pipeEvents(ctx, logger, recv, q, pt, updateTable)
		if dispatcher != nil {
			dispatcher.clear()
		}
		recv.Disconnect()

		if !reconnect {
			return
		}

		logger.InfoContext(ctx, "receiver reconnecting", "service", xpcService, "retry_in", initialBackoff)
		if !sleepCtx(ctx, initialBackoff) {
			return
		}
	}
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
