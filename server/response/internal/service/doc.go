// Package service is the response orchestrator: a single struct
// implementing api.Service from the mysql.Store + a Heartbeat
// closure. Status-transition rules + heartbeat invocation live here
// (no DB round-trip needed to test the transition matrix).
//
// Heartbeat advances the host's last-seen-ns on every /api/commands
// poll. cmd/main supplies the closure (today:
// detection.api.RecordHostSeen) so response stays free of an explicit
// detection dependency.
package service
