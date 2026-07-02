//go:build darwin

package config

// Default filesystem locations on macOS. The pkg installer drops the conf file at /etc and the agent keeps its queue + token under
// /var/db/fleet-edr. Vars, not consts, so the Windows build can compute its paths from %ProgramData% at init (paths_windows.go).
var (
	platformConfFile    = "/etc/fleet-edr.conf"
	platformQueueDBPath = "/var/db/fleet-edr/events.db"
	platformTokenFile   = "/var/db/fleet-edr/enrolled.plist" //nolint:gosec // path to the token file, not a credential.
)
