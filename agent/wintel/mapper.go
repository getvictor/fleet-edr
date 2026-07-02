// Package wintel is the Windows telemetry sensor: it consumes an ETW Kernel-Process session (via agent/wintel/etw) and maps its events
// into the platform-agnostic event envelope the agent uploads. The mapping in this file is pure (no Windows syscalls) so it is
// unit-testable on any OS; the live ETW consumer and the receiver.Connector implementation live in the windows-tagged files.
package wintel

import (
	"encoding/json"
	"strings"
)

// platformWindows is the envelope platform value the sensor stamps (matches the server's PlatformWindows / runtime.GOOS).
const platformWindows = "windows"

// filetimeEpochOffset is the number of 100-nanosecond ticks between the Windows FILETIME epoch (1601-01-01) and the Unix epoch
// (1970-01-01). Subtracting it converts a FILETIME to a Unix-relative tick count.
const filetimeEpochOffset = 116444736000000000

// envelope mirrors the event envelope in schema/events.json. On Windows the agent authors the envelope itself (unlike macOS, where the
// system extension serializes it), so this struct is the wire contract for Windows-produced events.
type envelope struct {
	EventID     string `json:"event_id"`
	HostID      string `json:"host_id"`
	TimestampNs int64  `json:"timestamp_ns"`
	EventType   string `json:"event_type"`
	Platform    string `json:"platform"`
	Payload     any    `json:"payload"`
}

// execPayload matches schema.exec_payload's required set. args is always a non-nil slice so it serializes as a JSON array, never null.
// Windows has no uid/gid, so those are zero (the ADR-0018 follow-up adds an optional user_sid). CreateTimeNs is the pid_epoch: the
// process creation time that disambiguates PID reuse, the Windows analogue of macOS pid_version.
type execPayload struct {
	PID          int      `json:"pid"`
	PPID         int      `json:"ppid"`
	Path         string   `json:"path"`
	Args         []string `json:"args"`
	Cwd          string   `json:"cwd"`
	UID          int      `json:"uid"`
	GID          int      `json:"gid"`
	CreateTimeNs int64    `json:"create_time_ns,omitempty"`
}

// exitPayload matches schema.exit_payload's required set, plus the optional create_time_ns so a consumer can pair an exit with the exec
// of the same (pid, create-time) generation.
type exitPayload struct {
	PID          int   `json:"pid"`
	ExitCode     int   `json:"exit_code"`
	CreateTimeNs int64 `json:"create_time_ns,omitempty"`
}

// filetimeToUnixNano converts a Windows FILETIME (100 ns ticks since 1601) to Unix nanoseconds. A zero FILETIME maps to zero so callers
// can treat "unknown" uniformly and rely on omitempty.
func filetimeToUnixNano(ft int64) int64 {
	if ft == 0 {
		return 0
	}
	return (ft - filetimeEpochOffset) * 100
}

// ntPathToDOS rewrites an NT device path (for example \Device\HarddiskVolume4\Windows\System32\cmd.exe) to a DOS path (C:\Windows\...)
// using a device-to-drive map (\Device\HarddiskVolume4 -> C:). A path with no matching device prefix is returned unchanged, so a
// volume the map does not cover degrades to the raw NT path rather than being dropped.
func ntPathToDOS(p string, deviceMap map[string]string) string {
	for device, drive := range deviceMap {
		if strings.HasPrefix(p, device+`\`) {
			return drive + p[len(device):]
		}
	}
	return p
}

// execEnvelope builds the JSON envelope for a process-start event.
func execEnvelope(eventID, hostID string, tsNs int64, p execPayload) ([]byte, error) {
	if p.Args == nil {
		p.Args = []string{}
	}
	return json.Marshal(envelope{EventID: eventID, HostID: hostID, TimestampNs: tsNs, EventType: "exec", Platform: platformWindows, Payload: p})
}

// exitEnvelope builds the JSON envelope for a process-stop event.
func exitEnvelope(eventID, hostID string, tsNs int64, p exitPayload) ([]byte, error) {
	return json.Marshal(envelope{EventID: eventID, HostID: hostID, TimestampNs: tsNs, EventType: "exit", Platform: platformWindows, Payload: p})
}
