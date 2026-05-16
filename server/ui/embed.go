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
// builds leave the var unset and serve the embedded copy.
const LiveDirEnv = "EDR_UI_LIVE_DIR"

// FS returns the filesystem the server should serve UI assets from.
//
//   - Production: the embedded bundle. Frozen at compile time, ships with the
//     binary, identical for every request.
//   - Dev: when EDR_UI_LIVE_DIR is set, reads from that directory on disk so
//     `task build:ui` refreshes the bundle on the next request without a
//     `task dev:server` restart. Vite's `emptyOutDir: true` clears the dist
//     directory before writing the new bundle, so a request that arrives mid-
//     rebuild (sub-second window on this codebase) can see missing files; the
//     SPA-fallback path in registerUIRoutes treats those as 404 and the next
//     request after the rebuild settles serves the new bundle.
//
// Returns an error if EDR_UI_LIVE_DIR points at a non-existent or unreadable
// path so a misconfigured dev server fails at boot with a clear message
// instead of 500ing every request.
func FS() (fs.FS, error) {
	if dir := os.Getenv(LiveDirEnv); dir != "" {
		if _, err := os.Stat(dir); err != nil { //nolint:gosec // dev-only env var, operator-supplied path is intentional
			return nil, fmt.Errorf("%s=%q: %w", LiveDirEnv, dir, err)
		}
		return os.DirFS(dir), nil
	}
	return fs.Sub(embeddedDist, "dist")
}
