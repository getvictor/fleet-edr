//go:build !darwin && !windows

package config

// Default filesystem locations on Linux and other Unix-like platforms. Kept identical to the macOS values so the existing
// build:agent:linux compile-parity and any Linux dev run behave exactly as before the platform split; a Linux agent can refine these
// when it lands.
var (
	platformConfFile    = "/etc/fleet-edr.conf"
	platformQueueDBPath = "/var/db/fleet-edr/events.db"
	platformTokenFile   = "/var/db/fleet-edr/enrolled.plist" //nolint:gosec // path to the token file, not a credential.
)
