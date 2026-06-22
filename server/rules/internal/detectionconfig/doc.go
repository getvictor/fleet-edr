// Package detectionconfig owns the DB-backed detection-configuration surface
// (issue #459): per-rule settings (mode / severity override / JSON settings)
// and typed false-positive exclusions, the replacement for the boot-time
// env-CSV allowlists + disabled-rule list.
//
// The Store persists and reads the two tables plus a version counter. A
// Snapshot is an immutable in-memory view loaded from the Store and handed to
// the catalog rules (as an api.ExclusionResolver) and the engine (as an
// api.RuleModeResolver); both resolve PER HOST. The snapshot is swapped on
// reload when the version advances, so a config change takes effect without a
// restart and each replica converges by re-reading MySQL (ADR-0010: the
// snapshot is a per-replica perf cache, safe to lose).
package detectionconfig
