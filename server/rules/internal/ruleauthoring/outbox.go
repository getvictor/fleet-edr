package ruleauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
)

// AuditOutboxKind names the encoding of an outbox payload. It is stored with every entry so a drain meeting an entry written by a
// newer version can leave it alone rather than decode it wrongly, which for an audit row would mean recording something that did
// not happen.
const AuditOutboxKind = "identity.audit_event.v1"

// DrainBatch is how many entries one drain pass takes. Small because the steady state is zero or one: an entry is written by an
// operator action and delivered by that same request, and the sweep exists for the ones a crash or a database blip left behind.
const DrainBatch = 100

// auditEntryV1 is the ON-DISK shape of an outbox payload, with explicit tags, and it is deliberately not identityapi.AuditEvent.
//
// The entry outlives the process that wrote it and may be read by a replica running different code, so its encoding is a format
// this package owns rather than whatever field names AuditEvent happens to have today. Marshalling the domain type directly would
// make a field rename in another context silently change a persisted format, which is the kind of coupling a durable encoding must
// not have. The tags are what AuditOutboxKind names: change either and the kind changes with it.
//
// Only the fields a rule-content audit row carries. TraceID and RemoteAddr are not among them: the recorder fills the trace id
// from the call's context, and the drain's context is the sweep's rather than the operator's request, so carrying one would
// attribute the row to the wrong call. That is a real loss against the old synchronous write and is the trade the outbox makes.
type auditEntryV1 struct {
	ActorID    string         `json:"actor_id"`
	ActorType  string         `json:"actor_type"`
	ActorLabel string         `json:"actor_label"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Payload    map[string]any `json:"payload,omitempty"`
}

// encodeAuditEntry turns an audit event into the opaque bytes rulecontent stores alongside the content change (issue #886).
//
// The encoding is this package's, not rulecontent's. That is the whole reason the outbox column is opaque: rulecontent commits the
// bytes with the change without learning what an audit event is, which is the boundary ADR-0021 sets and which a shared struct
// would cross.
func encodeAuditEntry(e identityapi.AuditEvent) (rulecontentapi.AuditOutboxEntry, error) {
	payload, err := json.Marshal(auditEntryV1{
		ActorID:    e.Actor.ID,
		ActorType:  string(e.Actor.Type),
		ActorLabel: e.Actor.Label,
		Action:     string(e.Action),
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		Payload:    e.Payload,
	})
	if err != nil {
		return rulecontentapi.AuditOutboxEntry{}, fmt.Errorf("encode audit outbox entry: %w", err)
	}
	return rulecontentapi.AuditOutboxEntry{Kind: AuditOutboxKind, Payload: payload}, nil
}

// decodeAuditEntry is encodeAuditEntry's inverse.
func decodeAuditEntry(payload []byte) (identityapi.AuditEvent, error) {
	var stored auditEntryV1
	if err := json.Unmarshal(payload, &stored); err != nil {
		return identityapi.AuditEvent{}, err
	}
	return identityapi.AuditEvent{
		Actor: identityapi.PrincipalRef{
			ID:    stored.ActorID,
			Type:  identityapi.PrincipalType(stored.ActorType),
			Label: stored.ActorLabel,
		},
		Action:     identityapi.AuditAction(stored.Action),
		TargetType: stored.TargetType,
		TargetID:   stored.TargetID,
		Payload:    stored.Payload,
	}, nil
}

// AuditDrain turns committed outbox entries into audit rows.
//
// Delivery is at-least-once and the audit log tolerates it, because an entry is deleted only after the recorder reports success:
// a crash between the two redelivers, which duplicates a row rather than losing one. That is the right direction for an
// append-only trail, where a duplicate is visible and a gap is not.
type AuditDrain struct {
	outbox rulecontentapi.AuditOutbox
	audit  identityapi.AuditRecorder
	logger *slog.Logger
}

// NewAuditDrain builds a drain. Every collaborator is required, for the same reason the services require their recorder: a drain
// with a missing piece is a wiring in which every rule-content change loses its audit row, silently.
func NewAuditDrain(
	outbox rulecontentapi.AuditOutbox, audit identityapi.AuditRecorder, logger *slog.Logger,
) (*AuditDrain, error) {
	if outbox == nil || audit == nil {
		return nil, errors.New("rule authoring audit drain: an outbox and an audit recorder are both required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &AuditDrain{outbox: outbox, audit: audit, logger: logger}, nil
}

// Drain delivers the pending entries, oldest first, and returns how many it delivered.
//
// Stops at the FIRST failure rather than skipping past it, and deletes only what it delivered. Order is the reason: the entries
// are a sequence of changes to what a fleet detects, and delivering a later one over a failed earlier one would produce a trail
// whose order disagrees with the changes it records. A stalled entry is retried on the next pass.
func (d *AuditDrain) Drain(ctx context.Context) (int, error) {
	pending, err := d.outbox.PendingAuditEntries(ctx, DrainBatch)
	if err != nil {
		return 0, err
	}
	delivered := make([]int64, 0, len(pending))
	var stopErr error
	for _, entry := range pending {
		if entry.Kind != AuditOutboxKind {
			// A kind this build does not know is left in place rather than dropped. During a rolling deployment the writer may
			// be a version ahead; deleting what it wrote would lose the audit row it was careful to make durable.
			d.logger.WarnContext(ctx, "rule content audit entry has an unknown encoding; leaving it for a newer replica",
				"id", entry.ID, "kind", entry.Kind)
			break
		}
		e, err := decodeAuditEntry(entry.Payload)
		if err != nil {
			// Also left in place, and this one is louder: an entry that cannot be decoded by the version that wrote its kind is
			// a defect, and dropping it would hide the defect by removing its evidence.
			d.logger.ErrorContext(ctx, "rule content audit entry could not be decoded; leaving it in the outbox",
				"id", entry.ID, "err", err)
			stopErr = fmt.Errorf("decode audit outbox entry %d: %w", entry.ID, err)
			break
		}
		if err := d.audit.Record(ctx, e); err != nil {
			stopErr = fmt.Errorf("record audit entry %d: %w", entry.ID, err)
			break
		}
		delivered = append(delivered, entry.ID)
	}
	if len(delivered) > 0 {
		if err := d.outbox.DeleteAuditEntries(ctx, delivered); err != nil {
			// The rows were recorded and the entries were not removed, so the next pass records them again. At-least-once is
			// the guarantee, so this is a duplicate rather than a loss, and it is worth a line because a persistent failure here
			// would show up as a repeating audit row.
			d.logger.ErrorContext(ctx, "delivered rule content audit entries but could not clear them; they will redeliver",
				"count", len(delivered), "err", err)
			return len(delivered), err
		}
	}
	return len(delivered), stopErr
}

// DefaultSweepInterval is how often the sweep looks for entries the request that wrote them could not deliver.
//
// A minute rather than seconds. The steady state is an empty table: an entry is written by an operator action and delivered by
// that same request, so the sweep only sees what a crash or a database blip left behind. Polling faster would buy latency on an
// audit row that is already durable, at the cost of a query per replica per interval against a table that is almost always empty.
const DefaultSweepInterval = time.Minute

// SweepLoop delivers entries left behind by a request that could not, until ctx is cancelled.
//
// Not leader-gated, and it does not need to be. The drain reads oldest-first and deletes only what it delivered, so two replicas
// running it concurrently either deliver disjoint sets or deliver the same entry twice. The second is the at-least-once the audit
// log already tolerates, and it is the direction to err in: a duplicate audit row is visible and a missing one is not.
func (d *AuditDrain) SweepLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultSweepInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			delivered, err := d.Drain(ctx)
			if err != nil {
				d.logger.ErrorContext(ctx, "sweeping rule content audit entries", "err", err)
			}
			if delivered > 0 {
				// Worth a line: reaching here means a request committed a change whose audit row it could not write, which is
				// the condition the outbox exists for and which nothing else would report.
				d.logger.InfoContext(ctx, "delivered rule content audit entries a request had left behind",
					"count", delivered)
			}
		}
	}
}
