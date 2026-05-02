// Package service is the response orchestrator: a single struct
// implementing api.Service from the mysql.Store + a Heartbeat
// closure. Status-transition rules + heartbeat invocation live here
// (no DB round-trip needed to test the transition matrix).
//
// Heartbeat advances the host's last-seen-ns on every /api/commands
// poll. cmd/main supplies store.UpdateHostLastSeen today; phase 5
// swaps the closure to detection.api.RecordHostSeen without churning
// the service surface.
package service
