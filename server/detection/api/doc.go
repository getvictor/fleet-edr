// Package api is the public surface of the detection bounded context.
//
// detection owns the EDR's hot path: event intake, process-graph
// materialisation, rule evaluation, alert persistence, retention sweep,
// stale-process janitor, plus the operator read surface for
// hosts / alerts / process trees.
//
// Cross-context callers consume detection through:
//
//   - Service: operator-facing reads (ListHosts, BuildTree,
//     GetProcessDetail, ListAlerts, GetAlert, UpdateAlertStatus),
//     metrics gauges (CountOfflineHosts, CountUnprocessed),
//     Heartbeat-style RecordHostSeen for response/internal/service,
//     and IngestHandler for cmd/main to mount POST /api/events.
//   - GraphReader: narrow read interface rules consume during
//     evaluation. *detection/internal/mysql.Store satisfies this
//     directly so rule.Evaluate gets non-allocating method dispatch.
//   - MetricsRecorder: optional OTel hook the engine + intake +
//     pipeline goroutines write to. Nil-safe.
//
// Per ADR-0004, detection/api is the canonical home for the domain
// types Event, Process, Host, Alert, AlertStatus, AlertFilter,
// ProcessNode, HostSummary, Finding, TimeRange, plus the SeverityLow /
// Medium / High / Critical constants. rules/internal/catalog imports
// these directly via `import detectionapi "...detection/api"`.
package api
