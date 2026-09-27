//go:build !darwin

package pkgsign

// Evaluate is unsupported off darwin, where there are no installer packages. The headless linux agent is fed synthetic events
// that already carry any package signature.
func Evaluate(_, _ string) (*Result, bool) { return nil, false }
