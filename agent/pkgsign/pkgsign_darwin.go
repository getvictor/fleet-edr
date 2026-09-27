//go:build darwin

package pkgsign

import (
	"context"
	"os/exec"
	"time"
)

// checkTimeout bounds one pkgutil run. A local check takes about 0.2 s; the bound is for a wedged process, which must not hold
// an event back indefinitely.
const checkTimeout = 5 * time.Second

// Evaluate reads the signature of the package at path. ok is false when pkgutil could not read it (absent, or removed before
// the check), in which case the event is left without a package signature and the rule treats it as unclassified.
func Evaluate(path string) (*Result, bool) {
	if path == "" {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	// pkgutil exits non-zero for an unsigned package, which is an answer rather than a failure, so the exit status is ignored
	// and the output decides.
	out, _ := exec.CommandContext(ctx, "/usr/sbin/pkgutil", "--check-signature", path).CombinedOutput() //nolint:gosec // fixed binary; path is one argument, not shell
	res, ok := Parse(string(out))
	if !ok {
		return nil, false
	}
	return &res, true
}
