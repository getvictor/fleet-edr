//go:build !darwin || !cgo

package codesign

import "testing"

// TestEvaluateStub pins the non-darwin contract: Evaluate is a no-op that
// returns (nil, false) so enrichment leaves any pre-populated signing intact.
func TestEvaluateStub(t *testing.T) {
	for _, path := range []string{"", "/bin/ls", "/no/such/binary"} {
		if res, ok := Evaluate(path); ok || res != nil {
			t.Errorf("Evaluate(%q) = (%v, %v), want (nil, false)", path, res, ok)
		}
	}
}
