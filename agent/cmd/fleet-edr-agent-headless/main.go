//go:build !darwin || !cgo

// fleet-edr-agent-headless is the test-only build of the agent's Go core. It wires the same enrollment + queue + uploader pipeline as
// the production agent, substitutes the non-darwin stub receiver for the XPC bridge, and exposes a unix-socket control plane so test
// scenarios can inject events. See UAT plan layer L3 in docs/testing-strategy.md.
//
// This file is the entrypoint only; the actual wiring lives in headless.go (Run) and control.go (HTTP handlers) so the logic stays
// covered by the integration test in headless_test.go. main.go is excluded from Sonar's new-code coverage gate via the
// **/cmd/**/main.go rule in sonar-project.properties.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/fleetdm/edr/agent/config"
	"github.com/fleetdm/edr/agent/enrollment"
)

func main() {
	if err := mainErr(); err != nil {
		fmt.Fprintf(os.Stderr, "fleet-edr-agent-headless: %v\n", err)
		os.Exit(1)
	}
}

func mainErr() error {
	socketPath := flag.String("control-socket", "", "unix socket path for the local control plane (required)")
	flag.Parse()
	if *socketPath == "" {
		return fmt.Errorf("--control-socket is required")
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.HostIDOverride == "" {
		return fmt.Errorf("EDR_HOST_ID is required outside macOS (no IOPlatformUUID to derive from)")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	tokenProvider, err := enrollment.Ensure(ctx, enrollment.Options{
		ServerURL:         cfg.ServerURL,
		EnrollSecret:      cfg.EnrollSecret,
		TokenFile:         cfg.TokenFile,
		ServerFingerprint: cfg.ServerFingerprint,
		AllowInsecure:     cfg.AllowInsecure,
		HostIDOverride:    cfg.HostIDOverride,
		AgentVersion:      "headless-dev",
		Logger:            logger,
	})
	if err != nil {
		return fmt.Errorf("enrollment: %w", err)
	}

	return Run(ctx, Options{
		ServerURL:      cfg.ServerURL,
		HostID:         tokenProvider.HostID(),
		QueuePath:      cfg.QueueDBPath,
		SocketPath:     *socketPath,
		TokenProvider:  tokenProvider,
		BatchSize:      cfg.BatchSize,
		UploadInterval: cfg.UploadInterval,
		Logger:         logger,
	})
}
