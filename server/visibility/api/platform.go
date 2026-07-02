package api

// Platform identifies the operating system that produced an event. It is a small closed set: the agent stamps it on every envelope
// (Phase 0 of Windows support, ADR-0018), the detection engine scopes rules by it, and the hosts view surfaces it. The values match
// Go's runtime.GOOS so the agent can report its platform without a translation table.
const (
	PlatformDarwin  = "darwin"
	PlatformWindows = "windows"
	PlatformLinux   = "linux"
)

// IsValidPlatform reports whether platform is one of the recognized platform values. Intake rejects an event carrying anything else,
// so an unknown platform cannot reach a store and later confuse rule scoping.
func IsValidPlatform(platform string) bool {
	switch platform {
	case PlatformDarwin, PlatformWindows, PlatformLinux:
		return true
	default:
		return false
	}
}

// NormalizePlatform maps an empty platform to PlatformDarwin and returns any other value unchanged. An empty value means the event
// came from an agent predating the platform-aware contract; those agents are macOS-only, so darwin is the correct legacy default.
// Callers validate a non-empty value with IsValidPlatform before normalizing; NormalizePlatform does not reject.
func NormalizePlatform(platform string) string {
	if platform == "" {
		return PlatformDarwin
	}
	return platform
}
