// Package graph builds the in-memory process tree from event batches
// and serves the operator's process-tree read queries.
//
//   - builder.go: ProcessBatch + ProcessSingleHost; the per-batch
//     fork/exec/exit reducer that materialises rows into the
//     processes table.
//   - query.go: ListHosts, BuildTree, GetProcessDetail; the read
//     surface the operator handler delegates to.
//   - reexec.go: same-PID re-exec linkage logic (issue #10).
//
// Inputs come from detection/internal/mysql.Store via the small
// reader interfaces declared at the top of each file (so unit tests
// can substitute fakes without spinning up MySQL).
package graph
