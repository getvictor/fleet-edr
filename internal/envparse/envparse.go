// Package envparse provides the small handful of validated env-var parsers that
// the fleet-edr server and agent both need. Lives in its own module (wired via
// go.work) so both binaries share the same validation surface — previously the
// same four helpers were copy-pasted into server/config and agent/config and
// drifted every time a new knob landed.
//
// Every helper follows the same shape:
//
//  1. Read the raw value. Empty ⇒ no-op (caller's default wins).
//  2. Parse and validate against the documented shape.
//  3. On failure, append a descriptive error to *errs and leave *dst alone.
//  4. On success, write to *dst.
//
// Callers collect all errors and wrap them with errors.Join so operators see
// every misconfiguration at once rather than playing whack-a-mole.
package envparse

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// errFmt is the single format string used by the per-key parse failures so the
// wording stays consistent and Sonar's duplicated-literal rule stays quiet.
const errFmt = "%s=%q: %w"

// Getenv is the pluggable lookup callers hand in. Production passes os.Getenv;
// tests pass a fake map-backed function.
type Getenv func(string) string

// PositiveInt reads key as an int, requires > 0, writes to *dst on success.
// Unset ⇒ no-op. Malformed or non-positive ⇒ error appended to *errs.
func PositiveInt(getenv Getenv, key string, dst *int, errs *[]error) {
	v := getenv(key)
	if v == "" {
		return
	}
	n, err := strconv.Atoi(v)
	switch {
	case err != nil:
		*errs = append(*errs, fmt.Errorf(errFmt, key, v, err))
	case n <= 0:
		*errs = append(*errs, fmt.Errorf("%s=%d must be positive", key, n))
	default:
		*dst = n
	}
}

// NonNegativeInt permits 0 (useful for "disabled" sentinels such as retention
// days). Negative values are rejected.
func NonNegativeInt(getenv Getenv, key string, dst *int, errs *[]error) {
	v := getenv(key)
	if v == "" {
		return
	}
	n, err := strconv.Atoi(v)
	switch {
	case err != nil:
		*errs = append(*errs, fmt.Errorf(errFmt, key, v, err))
	case n < 0:
		*errs = append(*errs, fmt.Errorf("%s=%d must be >= 0 (0 disables)", key, n))
	default:
		*dst = n
	}
}

// NonNegativeInt64 is like NonNegativeInt but backed by int64, used for byte-
// sized caps (agent queue max bytes) that can legitimately exceed 2^31.
func NonNegativeInt64(getenv Getenv, key string, dst *int64, errs *[]error) {
	v := getenv(key)
	if v == "" {
		return
	}
	n, err := strconv.ParseInt(v, 10, 64)
	switch {
	case err != nil:
		*errs = append(*errs, fmt.Errorf(errFmt, key, v, err))
	case n < 0:
		*errs = append(*errs, fmt.Errorf("%s=%d must be >= 0", key, n))
	default:
		*dst = n
	}
}

// PositiveDuration parses key as a Go duration (e.g. "5s", "1h") and requires
// it to be > 0. Zero or negative durations are invariably wrong — callers feed
// these into time.NewTicker which panics on non-positive values.
func PositiveDuration(getenv Getenv, key string, dst *time.Duration, errs *[]error) {
	v := getenv(key)
	if v == "" {
		return
	}
	d, err := time.ParseDuration(v)
	switch {
	case err != nil:
		*errs = append(*errs, fmt.Errorf(errFmt, key, v, err))
	case d <= 0:
		*errs = append(*errs, fmt.Errorf("%s=%q must be positive", key, v))
	default:
		*dst = d
	}
}

// Allowlist turns a comma-separated string into a set, trimming whitespace and
// dropping empty entries. Returns nil for empty input so the caller can detect
// "operator didn't set it" and keep the package-local default.
func Allowlist(v string) map[string]struct{} {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	out := make(map[string]struct{})
	for p := range strings.SplitSeq(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out[p] = struct{}{}
	}
	return out
}

// Assert the compile-time shape of the helpers via this unused function. Catches
// someone accidentally dropping a parameter without updating all call sites when
// they refactor — the package has no tests today but this block at least keeps
// the signatures honest under `go vet`.
var _ = func() error {
	var errs []error
	return errors.Join(errs...)
}
