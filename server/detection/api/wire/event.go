package wire

import (
	"encoding/json"

	"github.com/fleetdm/edr/server/detection/api"
)

// DecodeBatch parses a JSON array of events from the agent's POST body. Rejects malformed batches at the boundary so the ingest
// handler doesn't have to. Returns the decoded slice (nil-safe on empty body).
func DecodeBatch(body []byte) ([]api.Event, error) {
	var out []api.Event
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// EncodeBatch marshals the events back into a JSON array. Mirrors
// DecodeBatch so cross-source correlation tests can round-trip.
func EncodeBatch(events []api.Event) ([]byte, error) {
	return json.Marshal(events)
}
