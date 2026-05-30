//go:build !darwin || !cgo

package codesign

// Evaluate is unsupported off the darwin/cgo build. The headless linux agent
// (UAT M3) is fed synthetic events that already carry code-signing, so it
// never needs to compute it; returning (nil, false) makes enrichment a no-op
// and leaves any pre-populated executable_code_signing untouched.
func Evaluate(_ string) (*Result, bool) { return nil, false }
