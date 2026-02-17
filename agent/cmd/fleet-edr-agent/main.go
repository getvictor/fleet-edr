// fleet-edr-agent is the Go daemon that receives ESF events from the system
// extension over XPC, queues them in SQLite, and uploads them to the cloud
// ingestion server.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fleetdm/edr/agent/queue"
	"github.com/fleetdm/edr/agent/receiver"
	"github.com/fleetdm/edr/agent/uploader"
)

func main() {
	var (
		xpcService = flag.String("xpc-service", "com.fleet.edr.extension", "XPC Mach service name")
		dbPath     = flag.String("db", "/var/db/fleet-edr/events.db", "SQLite queue database path")
		serverURL  = flag.String("server-url", "http://localhost:8080", "Ingestion server URL")
		apiKey     = flag.String("api-key", "", "API key for ingestion server")
		batchSize  = flag.Int("batch-size", 100, "Upload batch size")
		interval   = flag.Duration("interval", time.Second, "Upload interval")
		pruneAge   = flag.Duration("prune-age", 24*time.Hour, "Prune uploaded events older than this")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("fleet-edr-agent starting")

	// Open the durable event queue.
	q, err := queue.Open(*dbPath)
	if err != nil {
		log.Fatalf("open queue: %v", err)
	}
	defer q.Close()

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

	// Start receiver → queue pipeline with automatic reconnect.
	go runReceiverLoop(ctx, *xpcService, q)

	// Start uploader.
	go func() {
		if err := up.Run(ctx); err != nil {
			log.Printf("uploader: %v", err)
		}
	}()

	// Periodic prune.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pruned, err := q.Prune(*pruneAge)
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

	depth, _ := q.Depth()
	log.Printf("shutdown complete, queue depth: %d", depth)
	os.Exit(0)
}

// runReceiverLoop connects to the XPC service and reconnects with exponential
// backoff when the connection is interrupted or invalidated (e.g. the system
// extension restarts).
func runReceiverLoop(ctx context.Context, xpcService string, q *queue.Queue) {
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
			log.Printf("receiver connect: %v (retrying in %v)", err, backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		log.Println("receiver: connected to XPC service")
		backoff = initialBackoff // Reset backoff on successful connect.

		reconnect := pipeEvents(ctx, recv, q)
		recv.Disconnect()

		if !reconnect {
			return // Context cancelled.
		}

		log.Printf("receiver: connection lost, reconnecting in %v", initialBackoff)
		if !sleepCtx(ctx, initialBackoff) {
			return
		}
	}
}

// pipeEvents reads from the receiver and enqueues events until the context is
// cancelled or the XPC connection is lost. Returns true if reconnect should be
// attempted, false if shutdown.
func pipeEvents(ctx context.Context, recv *receiver.Receiver, q *queue.Queue) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		case evt := <-recv.Events():
			if err := q.Enqueue(evt.Data); err != nil {
				log.Printf("enqueue: %v", err)
			}
		case errCode := <-recv.Errors():
			log.Printf("xpc error: %d", errCode)
			switch errCode {
			case receiver.ErrorConnectionInvalid, receiver.ErrorConnectionInterrupted, receiver.ErrorTerminated:
				return true // Reconnect.
			}
		}
	}
}

// sleepCtx sleeps for the given duration or until the context is cancelled.
// Returns true if the sleep completed, false if the context was cancelled.
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
