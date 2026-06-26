package api

import "encoding/json"

// Event mirrors a raw endpoint telemetry row. The agent posts these to
// /api/events; ingestion writes them to the EventArchive and enqueues
// them on the EventLog, and the detection engine evaluates rules over
// batches of these.
//
// Wire shape MUST stay byte-identical with what earlier server versions
// produced: agents in the field decode server-emitted Events for
// /api/commands result payloads. detection/api.Event aliases this type,
// so the JSON and db tags here are the canonical contract.
type Event struct {
	EventID      string          `db:"event_id" json:"event_id"`
	HostID       string          `db:"host_id" json:"host_id"`
	TimestampNs  int64           `db:"timestamp_ns" json:"timestamp_ns"`
	IngestedAtNs int64           `db:"ingested_at_ns" json:"ingested_at_ns,omitempty"`
	EventType    string          `db:"event_type" json:"event_type"`
	Payload      json.RawMessage `db:"payload" json:"payload"`
}
