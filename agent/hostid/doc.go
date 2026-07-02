// Package hostid derives a stable host identifier for use as the agent's host id. On macOS this is the hardware UUID (IOPlatformUUID),
// which matches what the system extension stamps into each event envelope so the agent's command poller is addressed by the same id that
// appears in the UI and server. On Windows it is the registry MachineGuid; other platforms return an error until they grow a source.
// The per-platform Get implementations live in hostid.go (darwin), hostid_windows.go, and hostid_other.go.
package hostid
