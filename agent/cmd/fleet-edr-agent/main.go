// fleet-edr-agent is the Go daemon that receives ESF and network events from
// system extensions over XPC, queues them in SQLite, and uploads them to the
// ingestion server. Configuration is loaded from environment variables; see
// agent/config for the full reference.
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

	"github.com/fleetdm/edr/agent/commander"
	"github.com/fleetdm/edr/agent/config"
	"github.com/fleetdm/edr/agent/hostid"
	"github.com/fleetdm/edr/agent/logging"
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

	q, err := queue.Open(ctx, cfg.QueueDBPath)
	if err != nil {
		logger.ErrorContext(ctx, "open queue", "err", err)
		return err
	}
	defer func() { _ = q.Close() }()

	pidTable := proctable.New()

	httpClient := &http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport),
		Timeout:   30 * time.Second,
	}

	up := uploader.New(q, uploader.Config{
		ServerURL:  cfg.ServerURL,
		APIKey:     cfg.BearerToken,
		BatchSize:  cfg.BatchSize,
		Interval:   cfg.UploadInterval,
		MaxRetries: 5,
	}, httpClient, logger)

	// Start ESF and network receiver loops.
	go runReceiverLoop(ctx, logger, cfg.XPCService, q, pidTable, true)
	if cfg.NetXPCService != "" {
		go runReceiverLoop(ctx, logger, cfg.NetXPCService, q, pidTable, false)
	}

	go func() {
		if err := up.Run(ctx); err != nil && ctx.Err() == nil {
			logger.ErrorContext(ctx, "uploader", "err", err)
		}
	}()

	// Commander
	if hostID != "" {
		cmdr := commander.New(commander.Config{
			ServerURL: cfg.ServerURL,
			APIKey:    cfg.BearerToken,
			HostID:    hostID,
			Interval:  5 * time.Second,
		}, &http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport), Timeout: 10 * time.Second}, logger)
		go func() {
			if err := cmdr.Run(ctx); err != nil && ctx.Err() == nil {
				logger.ErrorContext(ctx, "commander", "err", err)
			}
		}()
		logger.InfoContext(ctx, "commander polling", "host_id_prefix", safePrefix(hostID))
	} else {
		logger.WarnContext(ctx, "no host_id available; commander disabled")
	}

	// Periodic prune of uploaded events.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pruned, err := q.Prune(ctx, cfg.PruneAge)
				if err != nil {
					logger.WarnContext(ctx, "prune", "err", err)
				} else if pruned > 0 {
					logger.InfoContext(ctx, "pruned old events", "count", pruned)
				}
			}
		}
	}()

	<-ctx.Done()
	logger.InfoContext(context.Background(), "agent shutting down")

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	up.Drain(drainCtx)
	drainCancel()

	depth, _ := q.Depth(context.Background())
	logger.InfoContext(context.Background(), "shutdown queue depth", "depth", depth)

	otelCtx, otelCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer otelCancel()
	if err := shutdownOTel(otelCtx); err != nil {
		logger.WarnContext(otelCtx, "otel shutdown", "err", err)
	}
	return nil
}

func safePrefix(s string) string {
	if len(s) < 8 {
		return s
	}
	return s[:8]
}

// runReceiverLoop connects to an XPC service and reconnects with exponential backoff.
func runReceiverLoop(ctx context.Context, logger *slog.Logger, xpcService string, q *queue.Queue, pt *proctable.Table, updateTable bool) {
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

		reconnect := pipeEvents(ctx, logger, recv, q, pt, updateTable)
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
			logger.WarnContext(ctx, "xpc error", "code", errCode)
			switch errCode {
			case receiver.ErrorConnectionInvalid, receiver.ErrorConnectionInterrupted, receiver.ErrorTerminated:
				return true
			default:
				return true
			}
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
