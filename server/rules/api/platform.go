package api

// Platform identifies an operating system a detection rule targets. It mirrors the canonical platform vocabulary owned by the
// visibility bounded context (visibilityapi.Platform*): arch-go forbids a rules-context import of visibility/api, so the small closed
// set is duplicated here with the same values, matching the existing cross-context mirror pattern (see the AlertSource constants). The
// engine scopes a rule to events whose platform is in the rule's declared set (ADR-0018).
type Platform string

const (
	PlatformDarwin  Platform = "darwin"
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
)

// IsValidPlatform reports whether p is one of the recognized platform values. The catalog guard test asserts every rule declares only
// valid platforms.
func IsValidPlatform(p Platform) bool {
	switch p {
	case PlatformDarwin, PlatformWindows, PlatformLinux:
		return true
	default:
		return false
	}
}
