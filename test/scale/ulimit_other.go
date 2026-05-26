//go:build !linux

package scale

// ulimitCheckForHeadless is a no-op on platforms other than Linux. macOS dev boxes use launchd's per-process file-
// descriptor allowance (typically OPEN_MAX = 24576) which is comfortably above the 100-host headless budget. On Windows,
// ModeHeadless itself is unsupported (see the build-tag comment in runner_headless_unsupported.go - unix-domain sockets
// not available) so a no-op here is fine; the runtime check in runHeadless catches that path with a clear error before
// any FD allocation. The Linux variant in ulimit_linux.go carries the real check and the rationale.
func ulimitCheckForHeadless(_ int) error { return nil }
