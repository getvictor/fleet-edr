//go:build darwin && cgo

package scale

import (
	"context"
	"errors"
)

// runHeadless on darwin+cgo (production macOS dev box) returns a clear error rather than compile-failing the package. The
// real implementation lives in runner_headless.go behind the same build tag the headless package uses: `!darwin || !cgo`.
// Operators on macOS who need to exercise ModeHeadless rebuild with `CGO_ENABLED=0 go test ./test/scale/...` or run the
// scale-driver in a Linux container.
func runHeadless(_ context.Context, _ Options) (Report, error) {
	return Report{}, errors.New("scale: ModeHeadless is not supported on darwin with CGO enabled; rebuild with CGO_ENABLED=0 or use ModeDirect")
}
