//go:build !darwin || !cgo

package appbundle

// Path is unsupported off the darwin/cgo build, where there is no LaunchServices; the headless agent is fed events that already
// carry what enrichment would add.
func Path(_ string) (string, bool) { return "", false }
