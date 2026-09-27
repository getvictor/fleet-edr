//go:build !darwin || !cgo

package procpath

// Path is unsupported off the darwin/cgo build, where nothing asks for it.
func Path(_ int) (string, bool) { return "", false }
