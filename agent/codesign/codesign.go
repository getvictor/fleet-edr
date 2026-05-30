// Package codesign reads the on-disk code-signing identity of a macOS
// executable (or bundle) via the Security framework's SecStaticCode APIs.
//
// It exists so the agent — an unsandboxed root LaunchDaemon — can compute the
// code-signing of a BTM-registered executable that the sandboxed system
// extension cannot read on a SIP-enabled host. Doing the evaluation here, off
// the Endpoint Security callback thread, also keeps any signing-validation
// work away from the ES hot path where a network-touching check could deadlock
// the extension (ADR-0008, 2026-05-29 amendment).
//
// The darwin/cgo build links Security + CoreFoundation and is the production
// path; the non-darwin / CGO_ENABLED=0 build is a stub so the headless linux
// agent (UAT M3) still compiles. Off darwin the agent only ever sees synthetic
// events that already carry signing, so the stub's no-op is correct.
package codesign

// Result is the code-signing identity of an on-disk executable, in the wire shape of schema/events.json's `code_signing`
// definition ({team_id, signing_id, flags, is_platform_binary}). Marshalling a Result is what fills a btm_launch_item_add
// event's executable_code_signing field.
type Result struct {
	TeamID           string `json:"team_id"`
	SigningID        string `json:"signing_id"`
	Flags            int    `json:"flags"`
	IsPlatformBinary bool   `json:"is_platform_binary"`
}
