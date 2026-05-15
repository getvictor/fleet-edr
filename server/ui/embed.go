// Package ui embeds the built React frontend assets for serving by the Go server.
package ui

import (
	"embed"
	"io/fs"
	"os"
)

//go:embed all:dist
var embeddedDist embed.FS

// LiveDirEnv is the env var that opts a process into reading the UI bundle from
// disk instead of the compile-time embedded copy. Set by Taskfile's dev:server
// task to server/ui/dist so `task build:ui` is picked up without restarting the
// Go process. Production builds leave the var unset and serve the embedded copy.
const LiveDirEnv = "EDR_UI_LIVE_DIR"

// FS returns the filesystem the server should serve UI assets from.
//
//   - Production: the embedded bundle. Frozen at compile time, ships with the
//     binary, identical for every request.
//   - Dev: when EDR_UI_LIVE_DIR is set, reads from that directory on disk so
//     `task build:ui` refreshes the bundle on the next request without a
//     `task dev:server` restart. Vite writes new files atomically, so a request
//     in flight when the rebuild lands sees a coherent old-or-new snapshot.
func FS() (fs.FS, error) {
	if dir := os.Getenv(LiveDirEnv); dir != "" {
		return os.DirFS(dir), nil
	}
	return fs.Sub(embeddedDist, "dist")
}
