// Command scaledriver runs the M12 scale-test harness against an existing server. Boots no infrastructure of its own: the caller
// stands up the server (task dev:server or a release-candidate container), and this binary fans out N simulated hosts against
// the URL. Outputs a JSON report on stdout and (optionally) writes the same JSON to --output. Exit code is 0 on pass, 2 on fail.
//
// Defaults match the v0.1.0 baseline target: 100 hosts, 80/20 quiet/active mix, 5 minutes wall clock, p99 budget 250ms. The
// 30-minute baseline run the plan calls out is invoked via --duration=30m.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fleetdm/edr/test/scale"
)

// Defaults pulled out as named constants so the mnd linter's blanket objection lands once and the CLI flag block stays
// concise. None are security-sensitive; tweak via flags at the call site.
const (
	defaultHosts      = 100
	defaultQuietRatio = 0.8
	defaultDuration   = 5 * time.Minute
	defaultQuietGap   = 5 * time.Second
	defaultActiveGap  = 1 * time.Second
	defaultPassP99    = 250 * time.Millisecond
	exitFail          = 2
)

func main() {
	err := run()
	switch {
	case err == nil:
		return
	case errors.Is(err, errFail):
		os.Exit(exitFail)
	default:
		fmt.Fprintln(os.Stderr, "scaledriver:", err)
		os.Exit(1)
	}
}

func run() error {
	envEnrollSecret := os.Getenv("EDR_ENROLL_SECRET") //nolint:forbidigo // approved CLI-binary wiring boundary; see issue #172
	serverURL := flag.String("server-url", "https://localhost:8088", "EDR server base URL (no trailing slash)")
	enrollSecret := flag.String("enroll-secret", envEnrollSecret,
		"shared enroll secret (default from EDR_ENROLL_SECRET)")
	hostCount := flag.Int("hosts", defaultHosts, "number of simulated hosts")
	quietRatio := flag.Float64("quiet-ratio", defaultQuietRatio,
		"fraction of hosts assigned the quiet scenario; rest cycle active scenarios")
	duration := flag.Duration("duration", defaultDuration, "wall-clock duration of the load lane")
	quietGap := flag.Duration("quiet-gap", defaultQuietGap,
		"sleep between scenario iterations on quiet hosts (jittered +/- 25%)")
	activeGap := flag.Duration("active-gap", defaultActiveGap,
		"sleep between scenario iterations on active hosts (jittered +/- 25%)")
	passP99 := flag.Duration("pass-p99", defaultPassP99, "p99 ingest latency budget; exit 2 if exceeded")
	allowInsecure := flag.Bool("insecure-tls", true, "skip TLS verification (default true for dev:server's mkcert path)")
	scenarioDir := flag.String("scenario-dir", "", "root of scenario tree (defaults to repo-relative paths)")
	quietScenario := flag.String("quiet-scenario", "test/fakeagent/scenarios/quiet-host.yaml", "path to quiet-host scenario")
	activeScenarios := flag.String("active-scenarios", strings.Join([]string{
		"test/efficacy/corpus/T1059-suspicious-exec/scenario.yaml",
		"test/efficacy/corpus/T1543.001-launchagent-persistence/scenario.yaml",
		"test/efficacy/corpus/T1548.003-sudoers-tamper/scenario.yaml",
		"test/efficacy/corpus/T1555.001-keychain-dump/scenario.yaml",
	}, ","), "comma-separated active scenario paths cycled across active hosts")
	output := flag.String("output", "", "write the JSON report to this file in addition to stdout")
	flag.Parse()

	if *enrollSecret == "" {
		return errors.New("--enroll-secret (or EDR_ENROLL_SECRET) is required")
	}

	quietPath := *quietScenario
	if *scenarioDir != "" {
		quietPath = filepath.Join(*scenarioDir, quietPath)
	}
	activePaths := strings.Split(*activeScenarios, ",")
	for i, p := range activePaths {
		activePaths[i] = strings.TrimSpace(p)
		if *scenarioDir != "" {
			activePaths[i] = filepath.Join(*scenarioDir, activePaths[i])
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "scaledriver: %d hosts (%.0f%% quiet), %s, p99 budget %s vs %s\n",
		*hostCount, *quietRatio*100, *duration, *passP99, *serverURL)

	rep, err := scale.Run(ctx, scale.Options{
		ServerURL:           *serverURL,
		EnrollSecret:        *enrollSecret,
		HostCount:           *hostCount,
		QuietRatio:          *quietRatio,
		Duration:            *duration,
		QuietScenarioPath:   quietPath,
		ActiveScenarioPaths: activePaths,
		QuietIterationGap:   *quietGap,
		ActiveIterationGap:  *activeGap,
		AllowInsecureTLS:    *allowInsecure,
		PassP99:             *passP99,
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	if err := writeReport(os.Stdout, rep); err != nil {
		return err
	}
	if *output != "" {
		f, err := os.Create(*output) //nolint:gosec // output is a CLI-controlled path
		if err != nil {
			return fmt.Errorf("open --output: %w", err)
		}
		if err := writeReport(f, rep); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close --output: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "scaledriver: pass=%t p50=%s p95=%s p99=%s max=%s obs=%d errors=%d obs/sec=%.1f\n",
		rep.Pass, rep.LatencyP50, rep.LatencyP95, rep.LatencyP99, rep.LatencyMax,
		rep.ObservationCount, rep.ErrorCount, rep.ObservationsPerSec)
	if !rep.Pass {
		fmt.Fprintln(os.Stderr, "scaledriver: FAIL")
		for _, r := range rep.FailReasons {
			fmt.Fprintln(os.Stderr, "  -", r)
		}
		return errFail
	}
	return nil
}

// errFail is the sentinel returned for a clean fail-criteria breach. main() maps it to exit code 2 so the gocritic
// exitAfterDefer warning doesn't fire on an os.Exit() inline (defer cancel() in run() would otherwise be skipped).
var errFail = errors.New("scale criteria breached")

func writeReport(w io.Writer, rep scale.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
