// Package engine evaluates rules against event batches and persists
// findings as alerts.
//
// engine.go owns Engine plus its public API: Register, LoadActive,
// Evaluate, Catalog. SetMetrics installs the OTel counter hook.
// filter.go holds the snapshot-event filter (issue #11): exec events
// flagged `snapshot=true` represent ESF baseline enumeration and
// are dropped before rule evaluation so dyld_insert etc. don't
// fire false positives every time the extension restarts.
//
// The Rule interface itself lives in rules.api; engine consumes
// []rules.api.Rule and calls rule.Evaluate(ctx, events,
// detection.api.GraphReader). The Engine's store handle satisfies
// GraphReader directly so the inside-rule reads stay non-allocating.
package engine
