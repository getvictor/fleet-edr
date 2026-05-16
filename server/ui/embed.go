// Package ui embeds the built React frontend assets for serving by the Go server.
package ui

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
)

//go:embed all:dist
var embeddedDist embed.FS

// LiveDirEnv is the env var that opts a process into reading the UI bundle from disk instead of the compile-time embedded copy.
// Set by Taskfile's dev:server task to server/ui/dist so `task build:ui` is picked up without restarting the Go process. Production
// builds leave the var unset and serve the embedded copy. The cmd/main wiring resolves this once at startup and passes the value
// to FS; library code never reads process env so tests can drive the live-dir path without t.Setenv (issue #172).
const LiveDirEnv = "EDR_UI_LIVE_DIR"

// FS returns the filesystem the server should serve UI assets from. liveDir is the resolved value of EDR_UI_LIVE_DIR; pass "" to
// use the embedded bundle.
//
//   - Production: liveDir is empty, the embedded bundle is returned. Frozen
//     at compile time, ships with the binary, identical for every request.
//   - Dev: liveDir is the on-disk path so `task build:ui` refreshes the
//     bundle on the next request without a `task dev:server` restart. Vite's
//     `emptyOutDir: true` clears the dist directory before writing the new
//     bundle, so a request that arrives mid-rebuild (sub-second window on
//     this codebase) can see missing files; the SPA-fallback path in
//     registerUIRoutes treats those as 404 and the next request after the
//     rebuild settles serves the new bundle.
//
// Returns an error if liveDir is non-empty but points at a non-existent or unreadable path so a misconfigured dev server fails at
// boot with a clear message instead of 500ing every request.
func FS(liveDir string) (fs.FS, error) {
	if liveDir != "" {
		if _, err := os.Stat(liveDir); err != nil { //nolint:gosec // dev-only, operator-supplied path is intentional
			return nil, fmt.Errorf("%s=%q: %w", LiveDirEnv, liveDir, err)
		}
		return os.DirFS(liveDir), nil
	}
	return fs.Sub(embeddedDist, "dist")
}

// LiveDirFromEnv resolves EDR_UI_LIVE_DIR from the process environment. The single approved boundary where the env var is read;
// library and test code take the resolved string instead. Keeps the test-suite parallel-safe (issue #172).
func LiveDirFromEnv() string {
	return os.Getenv(LiveDirEnv) //nolint:forbidigo // approved wiring boundary; see issue #172
}
