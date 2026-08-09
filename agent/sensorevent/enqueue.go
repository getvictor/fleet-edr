package sensorevent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fleetdm/edr/internal/eventid"
)

// envelope is the on-the-wire shape the ingest handler expects. Duplicated locally rather than imported from the server,
// because the agent must not depend on server packages. Mirrors the same struct in agent/reconcile, which emits the other
// agent-synthesised events; `platform` is omitted there too and is not a required field in schema/events.json.
type envelope struct {
	EventID     string         `json:"event_id"`
	HostID      string         `json:"host_id"`
	TimestampNs int64          `json:"timestamp_ns"`
	EventType   string         `json:"event_type"`
	Payload     map[string]any `json:"payload"`
}

// NewEnqueueEmitter adapts the agent's queue to the Emitter seam.
//
// hostID is read per event rather than captured, because the value can change: the agent derives one before enrollment and
// adopts the server's afterwards, and an event carrying the pre-enrollment id would be attributed to a host that does not
// exist. nowNs is injected so tests pin timestamps.
func NewEnqueueEmitter(hostID func() string, enqueue func(context.Context, []byte) error, nowNs func() int64) Emitter {
	return func(ctx context.Context, eventType string, payload map[string]any) error {
		id, err := eventid.NewV4()
		if err != nil {
			return fmt.Errorf("generate event id: %w", err)
		}
		host := hostID()
		if host == "" {
			// Enrollment has not completed. Dropping is right rather than emitting with an empty host_id: an event nothing
			// can be attributed to is not evidence, and the extension re-publishes liveness on every handshake, so the
			// state is re-observed once enrollment lands.
			return errors.New("no host id yet")
		}
		body, err := json.Marshal(envelope{
			EventID:     id,
			HostID:      host,
			TimestampNs: nowNs(),
			EventType:   eventType,
			Payload:     payload,
		})
		if err != nil {
			return fmt.Errorf("marshal %s: %w", eventType, err)
		}
		return enqueue(ctx, body)
	}
}
