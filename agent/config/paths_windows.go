//go:build windows

package config

import (
	"os"
	"path/filepath"
)

// Default filesystem locations on Windows, under %ProgramData%\FleetEDR (the conventional home for per-machine service data). The MSI
// installer writes the conf file there; the agent keeps its queue and token alongside it. Computed at init from the ProgramData
// environment variable, falling back to the conventional C:\ProgramData when it is unset.
var (
	windowsDataDir      = windowsProgramDataDir()
	platformConfFile    = filepath.Join(windowsDataDir, "fleet-edr.conf")
	platformQueueDBPath = filepath.Join(windowsDataDir, "events.db")
	platformTokenFile   = filepath.Join(windowsDataDir, "enrolled.plist")
)

func windowsProgramDataDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "FleetEDR")
	}
	return filepath.Join(`C:\ProgramData`, "FleetEDR")
}
