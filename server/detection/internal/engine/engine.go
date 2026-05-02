package engine

// Engine is the rule-evaluation engine. The implementation is
// deliberately deferred: it must land together with the rules.api
// alias collapse (which retargets rules.api.Event / Process /
// TimeRange / Finding / GraphReader to detection.api) and the
// cmd/main wiring switch from detection.NewEngine(*store.Store) to
// detection/internal/engine.New(*detection/internal/mysql.Store).
// Until those land, calling rule.Evaluate on a detection.api event
// batch produces a type mismatch against the existing rules.api
// shape that aliases to server/store.
//
// The doc.go in this package describes the eventual surface
// (Engine, Register, LoadActive, Evaluate, Catalog, SetMetrics).
