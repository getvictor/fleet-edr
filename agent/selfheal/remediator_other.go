//go:build !darwin

package selfheal

// NewRemediator returns nil on platforms with no NetworkExtension capture providers to restore. A nil Remediator makes the
// controller a no-op, which is the honest behaviour here: there is nothing to heal, so there is nothing to report either.
// Mirrors the build-tag split the agent already uses for its other platform-specific paths (commander's kill, the receiver
// stub), so the linux headless build and the Windows compile check stay green.
func NewRemediator(string) Remediator {
	return nil
}
