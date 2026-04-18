// fleet-edr-agent is the Go daemon that receives ESF and network events from
// system extensions over XPC, queues them in SQLite, and uploads them to the
// cloud ingestion server.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fleetdm/edr/agent/commander"
	"github.com/fleetdm/edr/agent/hostid"
	"github.com/fleetdm/edr/agent/proctable"
	"github.com/fleetdm/edr/agent/queue"
	"github.com/fleetdm/edr/agent/receiver"
	"github.com/fleetdm/edr/agent/uploader"
)

func main() {
	var (
		xpcService    = flag.String("xpc-service", "8VBZ3948LU.com.fleetdm.edr.securityextension.xpc", "ESF extension XPC Mach service name")
		netXPCService = flag.String("net-xpc-service", "group.com.fleetdm.edr.networkextension", "Network extension XPC Mach service name")
		dbPath        = flag.String("db", "/var/db/fleet-edr/events.db", "SQLite queue database path")
		serverURL     = flag.String("server-url", "http://localhost:8088", "Ingestion server URL")
		apiKey        = flag.String("api-key", "", "API key for ingestion server")
		hostID        = flag.String("host-id", "", "Host identifier for command polling (defaults to the hardware IOPlatformUUID)")
		batchSize     = flag.Int("batch-size", 100, "Upload batch size")
		interval      = flag.Duration("interval", time.Second, "Upload interval")
		pruneAge      = flag.Duration("prune-age", 24*time.Hour, "Prune uploaded events older than this")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("fleet-edr-agent starting")

	// Open the durable event queue.
	q, err := queue.Open(context.Background(), *dbPath)
	if err != nil {
		log.Fatalf("open queue: %v", err)
	}
	defer func() { _ = q.Close() }()

	// In-memory PID table populated from ESF exec/exit events.
	pidTable := proctable.New()

	// Create the uploader.
	cfg := uploader.Config{
		ServerURL:  *serverURL,
		APIKey:     *apiKey,
		BatchSize:  *batchSize,
		Interval:   *interval,
		MaxRetries: 5,
	}
	up := uploader.New(q, cfg)

	// Set up graceful shutdown.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start ESF receiver → queue pipeline with PID table updates.
	go runReceiverLoop(ctx, *xpcService, q, pidTable, true)

	// Start network receiver → queue pipeline (reads PID table but doesn't write).
	if *netXPCService != "" {
		go runReceiverLoop(ctx, *netXPCService, q, pidTable, false)
	}

	// Start uploader.
	go func() {
		if err := up.Run(ctx); err != nil {
			log.Printf("uploader: %v", err)
		}
	}()

	// Start command polling. If -host-id wasn't provided, derive it from the
	// hardware IOPlatformUUID so the commander is always on by default. This is
	// the same id the system extension stamps into event envelopes.
	cmdHostID := *hostID
	if cmdHostID == "" {
		derived, err := hostid.Get(ctx)
		if err != nil {
			log.Printf("commander: cannot derive host-id from IOPlatformUUID: %v; command polling disabled", err)
		} else {
			cmdHostID = derived
			log.Printf("commander: derived host-id %.8s... from IOPlatformUUID", cmdHostID)
		}
	}
	if cmdHostID != "" {
		cmdr := commander.New(commander.Config{
			ServerURL: *serverURL,
			APIKey:    *apiKey,
			HostID:    cmdHostID,
			Interval:  5 * time.Second,
		})
		go func() {
			if err := cmdr.Run(ctx); err != nil {
				log.Printf("commander: %v", err)
			}
		}()
		log.Printf("commander: polling for commands as host %.8s...", cmdHostID)
	}

	// Periodic prune.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pruned, err := q.Prune(ctx, *pruneAge)
				if err != nil {
					log.Printf("prune: %v", err)
				} else if pruned > 0 {
					log.Printf("pruned %d old events", pruned)
				}
			}
		}
	}()

	<-ctx.Done()
	log.Println("fleet-edr-agent shutting down")

	// Give uploader a moment to drain in-flight uploads.
	time.Sleep(2 * time.Second)

	depth, _ := q.Depth(context.Background())
	log.Printf("shutdown complete, queue depth: %d", depth)
	os.Exit(0)
}

// runReceiverLoop connects to an XPC service and reconnects with exponential
// backoff when the connection is interrupted or invalidated.
func runReceiverLoop(ctx context.Context, xpcService string, q *queue.Queue, pt *proctable.Table, updateTable bool) {
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
			log.Printf("receiver(%s) connect: %v (retrying in %v)", xpcService, err, backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		log.Printf("receiver(%s): connected", xpcService)
		backoff = initialBackoff

		reconnect := pipeEvents(ctx, recv, q, pt, updateTable)
		recv.Disconnect()

		if !reconnect {
			return
		}

		log.Printf("receiver(%s): connection lost, reconnecting in %v", xpcService, initialBackoff)
		if !sleepCtx(ctx, initialBackoff) {
			return
		}
	}
}

// pipeEvents reads from the receiver and enqueues events until the context is
// cancelled or the XPC connection is lost. When updateTable is true, exec and
// exit events update the PID table.
func pipeEvents(ctx context.Context, recv *receiver.Receiver, q *queue.Queue, pt *proctable.Table, updateTable bool) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		case evt := <-recv.Events():
			if updateTable {
				updateProcTable(pt, evt.Data)
			}
			if err := q.Enqueue(ctx, evt.Data); err != nil {
				log.Printf("enqueue: %v", err)
			}
		case errCode := <-recv.Errors():
			log.Printf("xpc error: %d", errCode)
			switch errCode {
			case receiver.ErrorConnectionInvalid, receiver.ErrorConnectionInterrupted, receiver.ErrorTerminated:
				return true
			default:
				log.Printf("unknown xpc error code %d, reconnecting", errCode)
				return true
			}
		}
	}
}

// eventHeader is a minimal struct for peeking at event_type, pid, path, and uid
// without fully parsing the payload.
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

// updateProcTable parses just enough of the event to maintain the PID table.
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

// sleepCtx sleeps for the given duration or until the context is cancelled.
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
