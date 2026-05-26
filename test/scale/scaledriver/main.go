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
	defaultHosts                  = 100
	defaultQuietRatio             = 0.8
	defaultDuration               = 5 * time.Minute
	defaultQuietGap               = 5 * time.Second
	defaultActiveGap              = 1 * time.Second
	defaultPassP99                = 250 * time.Millisecond
	defaultQueueDepthPollInterval = time.Second
	exitFail                      = 2
)

// flagSet is the resolved CLI flag values + the runtime-only env-derived defaults. Parsing into a struct keeps run() under
// the cognitive-complexity budget: flag boilerplate moves to parseFlags, run() becomes orchestration.
type flagSet struct {
	serverURL              string
	enrollSecret           string
	hostCount              int
	quietRatio             float64
	duration               time.Duration
	quietGap               time.Duration
	activeGap              time.Duration
	passP99                time.Duration
	allowInsecure          bool
	scenarioDir            string
	quietScenario          string
	activeScenarios        string
	output                 string
	mode                   string
	queueDepthPollInterval time.Duration
	signozURL              string
	passMaxQueueDepth      int64
}

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
	fs := parseFlags()
	if fs.enrollSecret == "" {
		return errors.New("--enroll-secret (or EDR_ENROLL_SECRET) is required")
	}
	quietPath, activePaths, err := resolveScenarioPaths(fs)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "scaledriver: %d hosts (%.0f%% quiet), %s, p99 budget %s vs %s\n",
		fs.hostCount, fs.quietRatio*100, fs.duration, fs.passP99, fs.serverURL)

	rep, err := scale.Run(ctx, scale.Options{
		ServerURL:              fs.serverURL,
		EnrollSecret:           fs.enrollSecret,
		HostCount:              fs.hostCount,
		QuietRatio:             fs.quietRatio,
		Duration:               fs.duration,
		QuietScenarioPath:      quietPath,
		ActiveScenarioPaths:    activePaths,
		QuietIterationGap:      fs.quietGap,
		ActiveIterationGap:     fs.activeGap,
		AllowInsecureTLS:       fs.allowInsecure,
		PassP99:                fs.passP99,
		Mode:                   scale.Mode(fs.mode),
		QueueDepthPollInterval: fs.queueDepthPollInterval,
		SigNozURL:              fs.signozURL,
		PassMaxQueueDepth:      fs.passMaxQueueDepth,
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	if err := emitReport(rep, fs.output); err != nil {
		return err
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

// parseFlags wires every CLI flag onto a flagSet and calls flag.Parse(). Lives as its own helper so run() stays under the
// cognitive-complexity budget; the env-default fallback for EDR_ENROLL_SECRET also lives here for the same reason.
func parseFlags() flagSet {
	var fs flagSet
	envSecret := os.Getenv("EDR_ENROLL_SECRET") //nolint:forbidigo // approved CLI-binary wiring boundary; see issue #172
	flag.StringVar(&fs.serverURL, "server-url", "https://localhost:8088", "EDR server base URL (no trailing slash)")
	flag.StringVar(&fs.enrollSecret, "enroll-secret", envSecret, "shared enroll secret (default from EDR_ENROLL_SECRET)")
	flag.IntVar(&fs.hostCount, "hosts", defaultHosts, "number of simulated hosts")
	flag.Float64Var(&fs.quietRatio, "quiet-ratio", defaultQuietRatio,
		"fraction of hosts assigned the quiet scenario; rest cycle active scenarios")
	flag.DurationVar(&fs.duration, "duration", defaultDuration, "wall-clock duration of the load lane")
	flag.DurationVar(&fs.quietGap, "quiet-gap", defaultQuietGap,
		"sleep between scenario iterations on quiet hosts (jittered +/- 25%)")
	flag.DurationVar(&fs.activeGap, "active-gap", defaultActiveGap,
		"sleep between scenario iterations on active hosts (jittered +/- 25%)")
	flag.DurationVar(&fs.passP99, "pass-p99", defaultPassP99, "p99 ingest latency budget; exit 2 if exceeded")
	// Default to verifying TLS so a misconfigured caller cannot silently MITM a real server. Opt in only when targeting
	// dev:server's mkcert cert and the cert is NOT in the system trust store. CodeRabbit + Sonar both objected to the old
	// default-true behaviour; this flip is the resolution.
	flag.BoolVar(&fs.allowInsecure, "insecure-tls", false,
		"skip TLS verification (default false; opt-in for dev:server's mkcert path)")
	flag.StringVar(&fs.scenarioDir, "scenario-dir", "", "root of scenario tree (defaults to repo-relative paths)")
	flag.StringVar(&fs.quietScenario, "quiet-scenario", "test/fakeagent/scenarios/quiet-host.yaml",
		"path to quiet-host scenario")
	flag.StringVar(&fs.activeScenarios, "active-scenarios", strings.Join([]string{
		"test/efficacy/corpus/T1059-suspicious-exec/scenario.yaml",
		"test/efficacy/corpus/T1543.001-launchagent-persistence/scenario.yaml",
		"test/efficacy/corpus/T1548.003-sudoers-tamper/scenario.yaml",
		"test/efficacy/corpus/T1555.001-keychain-dump/scenario.yaml",
	}, ","), "comma-separated active scenario paths cycled across active hosts")
	flag.StringVar(&fs.output, "output", "", "write the JSON report to this file in addition to stdout")
	flag.StringVar(&fs.mode, "mode", string(scale.ModeDirect),
		"load shape: `direct` (v1 PostDirect against /api/events) or `headless` (v2 per-host headless.Run + queue-depth probe)")
	flag.DurationVar(&fs.queueDepthPollInterval, "queue-depth-poll-interval", defaultQueueDepthPollInterval,
		"cadence of GET /state polls in headless mode")
	flag.StringVar(&fs.signozURL, "signoz-url", "",
		"optional SigNoz base URL (e.g. http://localhost:8080); when set the report includes server-side p99 + client-vs-server delta")
	flag.Int64Var(&fs.passMaxQueueDepth, "pass-max-queue-depth", 0,
		"optional max-queue-depth ceiling; exit 2 if any host's max queue_depth exceeds this value (0 disables the gate)")
	flag.Parse()
	return fs
}

// resolveScenarioPaths trims and prefixes scenario paths against the optional --scenario-dir root, dropping empty entries
// from the active-scenarios comma list (a trailing comma is otherwise expanded into an empty path and failed later with a
// less-clear error). Returns the quiet path plus a non-empty list of active paths.
func resolveScenarioPaths(fs flagSet) (string, []string, error) {
	quiet := fs.quietScenario
	if fs.scenarioDir != "" {
		quiet = filepath.Join(fs.scenarioDir, quiet)
	}
	raw := strings.Split(fs.activeScenarios, ",")
	active := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if fs.scenarioDir != "" {
			p = filepath.Join(fs.scenarioDir, p)
		}
		active = append(active, p)
	}
	if fs.quietRatio < 1 && len(active) == 0 {
		return "", nil, errors.New("--active-scenarios must contain at least one path when quiet-ratio < 1")
	}
	return quiet, active, nil
}

// emitReport writes the JSON report to stdout and (optionally) the --output file. Split out so run()'s body stays linear.
func emitReport(rep scale.Report, outPath string) error {
	if err := writeReport(os.Stdout, rep); err != nil {
		return err
	}
	if outPath == "" {
		return nil
	}
	f, err := os.Create(outPath) //nolint:gosec // output is a CLI-controlled path
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
