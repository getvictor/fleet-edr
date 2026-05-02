package engine

// filterSnapshotEvents implements the issue #11 baseline-event drop
// (exec events flagged `snapshot=true` are ESF baseline enumeration,
// not new attacker activity, and must be excluded before rule
// evaluation to avoid false positives every time the extension
// restarts).
//
// The implementation lives alongside Engine in engine.go; this
// package's filter.go file slot is reserved for that placement
// (matches the detection/internal/engine layout described in
// detection/internal/engine/doc.go).
