//go:build !darwin || !cgo

package appbundle

// Paths is unsupported off the darwin/cgo build, where there is no LaunchServices; the headless agent is fed events that already
// carry what enrichment would add.
func Paths(_ string) []string { return nil }
