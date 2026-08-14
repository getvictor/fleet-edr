package full_test

import (
	"testing"

	"github.com/fleetdm/edr/server/testdb/full"
)

// BenchmarkOpen measures the fixture every database-backed integration test pays before its first line runs.
//
// It exists because this fixture was optimised (issue: the detection integration package calls it 109 times and was timing
// out in CI), and an optimisation nobody can measure is one that quietly regresses. The first iteration builds the schema by
// running all seven contexts' migrations; every iteration after replays the captured DDL, which is the path that matters.
//
// Run it with a real MySQL: EDR_TEST_DSN=... go test -run XXX -bench BenchmarkOpen ./server/testdb/full/
func BenchmarkOpen(b *testing.B) {
	for b.Loop() {
		_ = full.Open(b)
	}
}
