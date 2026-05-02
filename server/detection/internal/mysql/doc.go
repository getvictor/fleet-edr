// Package mysql is the persistence layer for the detection bounded
// context. Owns the events, processes, alerts, alert_events, and
// hosts tables.
//
// One Store struct holds the *sqlx.DB handle and exposes the per-
// table operations grouped by file:
//
//   - events.go: InsertEvents, FetchUnprocessed, MarkProcessed,
//     UnclaimEvents, CountEvents, CountUnprocessed.
//   - processes.go: InsertProcess, GetProcessByPID, GetChildProcesses,
//     GetExecChain, ProcessTTL helpers.
//   - hosts.go: UpsertHosts, UpdateHostLastSeen, ListHosts,
//     CountOfflineHosts.
//   - alerts.go: InsertAlert (with dedup), GetAlert, ListAlerts,
//     UpdateAlertStatus.
//
// The Store satisfies api.GraphReader directly so rule.Evaluate
// gets non-allocating method dispatch in the rule hot path.
//
// Allowed imports for tests in this package:
//   - detection/api;
//   - server/bootstrap (for OpenTestDB);
//   - platform + standard library + approved third-party.
package mysql
