//go:build !linux

package scale

// ulimitCheckForHeadless is a no-op on platforms other than Linux. macOS dev boxes use launchd's per-process file-descriptor
// allowance (typically OPEN_MAX = 24576) which is comfortably above the 100-host headless budget; Windows is not a target
// platform for the headless package (build tag !darwin || !cgo gates the package itself). The Linux variant in ulimit_linux.go
// carries the real check and the rationale.
func ulimitCheckForHeadless(_ int) error { return nil }
