//go:build windows || (darwin && cgo)

package scale

import (
	"context"
	"errors"
)

// runHeadless on platforms where the real implementation is gated out returns a clear error rather than compile-failing
// the package. Two unsupported configurations end up here:
//
//	darwin + cgo: the headless package itself is gated `!darwin || !cgo` so darwin-with-CGO can't import it. Operators
//	  on macOS who need ModeHeadless rebuild with `CGO_ENABLED=0 go test ./test/scale/...` or run the scale-driver in a
//	  Linux container.
//	windows: the headless package compiles but unix-domain sockets are not supported on Windows (net.Listen "unix" fails
//	  at runtime). Until Windows gets a named-pipe control-plane variant, ModeHeadless on Windows is not exercised
//	  (Copilot #277: tightened the build tag here so this stub is the live runHeadless on Windows).
func runHeadless(_ context.Context, _ Options) (Report, error) {
	return Report{}, errors.New("scale: ModeHeadless is not supported on this platform (darwin+cgo or windows); rebuild with CGO_ENABLED=0 on darwin or use ModeDirect")
}
