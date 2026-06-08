// Command fleet-edr-demo-seed preloads a running EDR server with demo data so the repo is evaluable in minutes without a Mac fleet.
//
// It enrols synthetic hosts, replays a curated attack + noise corpus through the real ingest API so the server's own processor builds
// the process graph and fires detection alerts, fabricates one application-control block, verifies the data materialised, and
// optionally provisions the SSO demo user at a full-capability role. It writes nothing the running server could not have produced,
// except the demo-user rows (an operator action), so the demo stays faithful to the real pipeline.
//
// It is meant to run as a one-shot container in docker-compose.demo.yml, but runs equally well by hand against `task dev:server`:
//
//	go run ./server/cmd/fleet-edr-demo-seed \
//	  --server-url https://localhost:8088 --enroll-secret dev-enroll-secret \
//	  --dsn 'root:@tcp(127.0.0.1:33306)/edr?parseTime=true'
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	// Wiring boundary: env + args are read here and passed into realMain as values (issue #172).
	if err := realMain(logger, os.Getenv, os.Args[1:]); err != nil { //nolint:forbidigo // wiring boundary, lifted into resolveConfig
		logger.ErrorContext(context.Background(), "demo seed failed", "err", err)
		os.Exit(1)
	}
}

// realMain resolves config, opens the database, and runs the seeder. getenv + args are injected so it is testable without mutating
// process state. Split out from main so the exit-code path stays a one-liner.
func realMain(logger *slog.Logger, getenv func(string) string, args []string) error {
	cfg, err := resolveConfig(getenv, args)
	if err != nil {
		return err
	}

	db, err := sql.Open("mysql", cfg.dsn)
	if err != nil {
		return fmt.Errorf("open mysql: %w", err)
	}
	defer db.Close()

	// Budget the overall run at the readiness + verification windows plus headroom for enroll/ingest round-trips.
	ctx, cancel := context.WithTimeout(context.Background(), cfg.readyTimeout+cfg.verifyTimeout+30*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping mysql: %w", err)
	}

	return newSeeder(cfg, db, logger).run(ctx)
}
