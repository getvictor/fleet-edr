// loadtest is a standalone tool that generates synthetic EDR events and sends
// them to the ingestion server to verify throughput, latency, and correctness.
//
// Usage:
//
//	go run test/loadtest.go -server-url http://localhost:8080 -rate 1000 -duration 60s
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type event struct {
	EventID     string          `json:"event_id"`
	HostID      string          `json:"host_id"`
	TimestampNs int64           `json:"timestamp_ns"`
	EventType   string          `json:"event_type"`
	Payload     json.RawMessage `json:"payload"`
}

func main() {
	var (
		serverURL = flag.String("server-url", "http://localhost:8080", "Ingestion server URL")
		apiKey    = flag.String("api-key", "", "API key")
		rate      = flag.Int("rate", 1000, "Events per minute")
		duration  = flag.Duration("duration", 60*time.Second, "Test duration")
		batchSize = flag.Int("batch-size", 50, "Events per HTTP request")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("load test: %d events/min for %v against %s", *rate, *duration, *serverURL)

	client := &http.Client{Timeout: 30 * time.Second}
	url := *serverURL + "/api/v1/events"

	var (
		sent       atomic.Int64
		errors     atomic.Int64
		totalLatNs atomic.Int64
	)

	// Calculate interval between batches to achieve target rate.
	batchesPerMinute := float64(*rate) / float64(*batchSize)
	batchInterval := time.Duration(float64(time.Minute) / batchesPerMinute)

	log.Printf("batch size: %d, interval: %v, batches/min: %.0f", *batchSize, batchInterval, batchesPerMinute)

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	var wg sync.WaitGroup
	hostID := fmt.Sprintf("loadtest-%d", os.Getpid())

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			printSummary(sent.Load(), errors.Load(), totalLatNs.Load(), *duration)
			return
		case <-ticker.C:
			wg.Go(func() {
				batch := generateBatch(*batchSize, hostID)
				start := time.Now()

				if err := sendBatch(ctx, client, url, *apiKey, batch); err != nil {
					errors.Add(1)
					log.Printf("send error: %v", err)
					return
				}

				latency := time.Since(start)
				totalLatNs.Add(latency.Nanoseconds())
				sent.Add(int64(*batchSize))
			})
		}
	}
}

func generateBatch(size int, hostID string) []event {
	paths := []string{
		"/usr/bin/ls", "/usr/bin/cat", "/usr/bin/grep", "/usr/bin/awk",
		"/usr/bin/sed", "/usr/bin/curl", "/usr/bin/true", "/usr/bin/false",
		"/usr/bin/env", "/usr/bin/head",
	}

	batch := make([]event, size)
	for i := range size {
		// math/rand/v2 is fine here: load-test payloads are synthetic data, not
		// cryptographic material. The gosec G404 warning is silenced by the v2
		// import (its auto-seeded RNG is the idiomatic replacement for the old
		// math/rand default source).
		pid := rand.IntN(65535) + 100
		path := paths[rand.IntN(len(paths))]

		payload, _ := json.Marshal(map[string]any{
			"pid":  pid,
			"ppid": 1,
			"path": path,
			"args": []string{path},
			"cwd":  "/tmp",
			"uid":  501,
			"gid":  20,
		})

		batch[i] = event{
			EventID:     fmt.Sprintf("%d-%d-%d", time.Now().UnixNano(), i, rand.Int()),
			HostID:      hostID,
			TimestampNs: time.Now().UnixNano(),
			EventType:   "exec",
			Payload:     payload,
		}
	}
	return batch
}

func sendBatch(ctx context.Context, client *http.Client, url, apiKey string, batch []event) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

func printSummary(sent, errors, totalLatNs int64, duration time.Duration) {
	log.Println("=== load test summary ===")
	log.Printf("duration:       %v", duration)
	log.Printf("events sent:    %d", sent)
	log.Printf("errors:         %d", errors)
	log.Printf("rate:           %.0f events/min", float64(sent)/duration.Minutes())

	if sent > 0 {
		batchCount := sent / 50 // approximate
		if batchCount == 0 {
			batchCount = 1
		}
		avgLatMs := float64(totalLatNs) / float64(batchCount) / 1e6
		log.Printf("avg batch lat:  %.1f ms", avgLatMs)
	}

	if errors > 0 {
		log.Printf("FAIL: %d errors encountered", errors)
		os.Exit(1)
	}
	log.Println("PASS: no errors")
}
