//go:build linux

package scale

import (
	"fmt"
	"log/slog"
	"syscall"
)

// fdsPerHeadlessHost is the per-host RLIMIT_NOFILE budget the ulimit pre-flight uses. Each headless host opens:
//
//   - 1 SQLite WAL file + its journal file (queue.db, queue.db-wal)
//   - 1 listening unix socket on the control plane
//   - A short-lived client unix-socket connection per /state poll + per scenario feed
//   - A keepalive TCP connection (pooled) to the EDR server's /api/events
//
// Steady-state is ~5 FDs per host. The 10 here is 2x headroom for transient bursts (scenario feed + /state poll
// overlapping with an in-flight uploader POST).
const fdsPerHeadlessHost = 10

// ulimitCheckForHeadless is the Linux pre-flight that the M12 issue called out as a fail-fast requirement: a 100-host
// headless lane against the default 1024 RLIMIT_NOFILE exhausts file descriptors mid-run with EMFILE in a confusing
// place (typically inside SQLite WAL rotation), so the runner refuses to start when the soft limit is below an honest
// budget. The 10x-per-host multiplier covers steady-state + scenario-feed + /state-poll bursts. Operators raise the
// limit with `ulimit -n 4096` in their shell or by writing 4096 into /etc/security/limits.conf for headless CI runs.
func ulimitCheckForHeadless(hostCount int) error {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		// Getrlimit failure is rare on Linux (it's a vDSO syscall) and not catastrophic - the caller can still try the
		// run and discover the EMFILE on the run path. Surface as a soft warning (not an error) so a kernel that
		// rejects the call (containers, seccomp policies) does not block headless mode entirely. Logging is what makes
		// it visible to operators (Copilot #277 - the previous silent-return left them guessing whether the pre-flight
		// ran).
		slog.Default().Warn("scale: RLIMIT_NOFILE pre-flight skipped (Getrlimit failed); continuing without FD check",
			"err", err)
		return nil //nolint:nilerr // syscall is non-fatal pre-flight; the run itself will surface a real problem
	}
	want := uint64(hostCount) * fdsPerHeadlessHost
	if lim.Cur >= want {
		return nil
	}
	return fmt.Errorf("scale: RLIMIT_NOFILE soft limit (%d) is below the headless-mode budget (%d hosts * %d fds = %d); raise with `ulimit -n %d`",
		lim.Cur, hostCount, fdsPerHeadlessHost, want, want)
}
