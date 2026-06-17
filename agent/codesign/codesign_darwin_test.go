//go:build darwin && cgo

package codesign

import (
	"os"
	"testing"
)

func TestEvaluate(t *testing.T) {
	t.Run("empty path returns not-ok", testEvaluateEmptyPath)
	t.Run("absent path returns not-ok", testEvaluateAbsentPath)
	t.Run("apple platform binary", testEvaluateApplePlatformBinary)
	t.Run("non-Apple binary is readable but not a platform binary", testEvaluateNonAppleBinary)
}

func testEvaluateEmptyPath(t *testing.T) {
	if res, ok := Evaluate(""); ok || res != nil {
		t.Fatalf("Evaluate(\"\") = (%v, %v), want (nil, false)", res, ok)
	}
}

func testEvaluateAbsentPath(t *testing.T) {
	if res, ok := Evaluate("/no/such/binary/edr-codesign-test"); ok || res != nil {
		t.Fatalf("Evaluate(absent) = (%v, %v), want (nil, false)", res, ok)
	}
}

func testEvaluateApplePlatformBinary(t *testing.T) {
	// /bin/ls is a SIP-protected Apple platform binary on every supported macOS, so this is stable ground truth.
	res, ok := Evaluate("/bin/ls")
	if !ok || res == nil {
		t.Fatalf("Evaluate(/bin/ls) = (%v, %v), want a result with ok=true", res, ok)
	}
	if !res.IsPlatformBinary {
		t.Errorf("IsPlatformBinary = false, want true for /bin/ls")
	}
	// Apple platform binaries carry no third-party team ID.
	if res.TeamID != "" {
		t.Errorf("TeamID = %q, want empty for an Apple platform binary", res.TeamID)
	}
	// Apple's own binaries do carry a signing identifier (e.g. com.apple.ls); assert it is populated rather than pinning
	// the exact value, which can drift across OS builds.
	if res.SigningID == "" {
		t.Errorf("SigningID is empty, want a non-empty Apple signing identifier for /bin/ls")
	}
}

func testEvaluateNonAppleBinary(t *testing.T) {
	// The test binary is a real Mach-O the Go toolchain ad-hoc signs on Apple Silicon: it carries no Developer team
	// ID and is not Apple-anchored. This is the attacker shape the rule fires on: present and readable, but untrusted.
	self, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable unavailable: %v", err)
	}
	res, ok := Evaluate(self)
	if !ok || res == nil {
		t.Fatalf("Evaluate(self) = (%v, %v), want a readable result", res, ok)
	}
	if res.IsPlatformBinary {
		t.Errorf("IsPlatformBinary = true, want false for an ad-hoc-signed non-Apple binary")
	}
	if res.TeamID != "" {
		t.Errorf("TeamID = %q, want empty for an ad-hoc-signed binary", res.TeamID)
	}
}
