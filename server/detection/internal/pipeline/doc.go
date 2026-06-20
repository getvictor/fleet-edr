// Package pipeline composes the three background goroutines detection
// runs continuously:
//
//   - processor.go: every config.DefaultProcessInterval, claim a batch
//     of unprocessed events, build the graph, evaluate rules, mark
//     processed.
//   - processttl.go: every config.DefaultStaleProcessInterval,
//     force-complete processes whose fork landed but exit never did (issue #6).
//   - retention.go: every config.DefaultRetentionInterval, drop events
//     older than cfg.RetentionDays (and cascading process / alert rows
//     that are no longer reachable).
//
// runner.go composes the three under one Run(ctx) so cmd/main
// launches them with a single goroutine. Each loop honours ctx
// cancellation; the runner returns when all three return.
//
// fleet-edr-ingest binary uses Mode: ModeIntake which skips the
// pipeline entirely.
package pipeline
