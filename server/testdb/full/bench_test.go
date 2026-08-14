package full_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/fleetdm/edr/server/testdb/full"
)

// BenchmarkOpen measures the fixture every database-backed integration test pays before its first line runs.
//
// It exists because this fixture was optimised (the detection integration package calls it 109 times and was timing out in
// CI), and an optimisation nobody can measure is one that quietly regresses. The first iteration builds the schema by running
// all seven contexts' migrations; every iteration after replays the captured DDL, which is the path that matters.
//
// Run it with a real MySQL: EDR_TEST_DSN=... go test -run XXX -bench BenchmarkOpen ./server/testdb/full/
func BenchmarkOpen(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		// Each iteration gets its own TB so its database is created under a distinct name AND torn down immediately.
		// Handing `b` straight to Open would register every iteration's cleanup against the whole benchmark, so a run
		// would hold one connection pool and one live database per iteration and exhaust the server's connection limit
		// well before it finished.
		iter := &benchTB{B: b, name: fmt.Sprintf("BenchmarkOpen_%d", i)}
		_ = full.Open(iter)

		// The teardown is real work (DROP DATABASE) and is not what this benchmark measures.
		b.StopTimer()
		iter.runCleanups()
		b.StartTimer()
	}
}

// benchTB adapts *testing.B so a benchmark can own the lifecycle of each iteration's fixture.
//
// Embedding *testing.B is what makes it a testing.TB: the interface has an unexported method, so it cannot be implemented
// from outside the testing package. Only Name and Cleanup are overridden; everything else, including the context Open uses,
// comes from the embedded B.
type benchTB struct {
	*testing.B
	name     string
	cleanups []func()
}

// Name gives each iteration a distinct database, since testdb derives the name from it.
func (b *benchTB) Name() string { return b.name }

// Cleanup collects rather than defers, so runCleanups can fire them between iterations.
func (b *benchTB) Cleanup(f func()) { b.cleanups = append(b.cleanups, f) }

// runCleanups unwinds in reverse registration order, matching what testing does, so the pool is closed before its database is
// dropped.
func (b *benchTB) runCleanups() {
	for _, cleanup := range slices.Backward(b.cleanups) {
		cleanup()
	}
	b.cleanups = nil
}
