// Package auditoutbox delivers audit rows that were committed in the same transaction as the change they record.
//
// The audit store sits behind an interface the identity context owns, so a change stored by another context cannot enlist it in its
// own transaction. The change's transaction instead writes an outbox entry, which commits if and only if the change does, and a
// drain turns entries into audit rows afterwards. Rule content (issue #886) and detection configuration (issue #1022) both write
// entries in this encoding, each into its own table, and each drains its table with a Drain.
//
// The package sits beside sqlhelpers and httpserver rather than inside a context because more than one context needs it, and it
// names identity/api, the one context dependency any encoding of an audit event must have (ADR-0021). A context supplies only its
// own table, so a second context writing entries adds a table and a wiring line rather than another copy of this file.
package auditoutbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/trace"

	identityapi "github.com/fleetdm/edr/server/identity/api"
)

// Entry is an encoded audit event, ready to be written into an outbox inside the transaction that makes the change.
type Entry struct {
	// Kind names the encoding, so a drain meeting an entry from a newer version can leave it rather than mis-decode it.
	Kind string
	// Payload is the encoded event, valid JSON.
	Payload []byte
}

// Pending is one undelivered outbox entry, as a drain reads it.
type Pending struct {
	ID      int64
	Kind    string
	Payload []byte
}

// Outbox is what a drain needs of an outbox table: the oldest deliverable entries, and deletion of the delivered ones.
type Outbox interface {
	// PendingAuditEntries returns up to limit deliverable entries, oldest first, so audit rows land in the order the changes did.
	PendingAuditEntries(ctx context.Context, limit int) ([]Pending, error)
	// DeleteAuditEntries removes entries that were delivered. Deleting is what marks delivery, so it runs after the recorder
	// accepted them.
	DeleteAuditEntries(ctx context.Context, ids []int64) error
}

// Kind names the encoding of an outbox payload. It is stored with every entry so a drain meeting an entry written by a
// newer version can leave it alone rather than decode it wrongly, which for an audit row would mean recording something that did
// not happen.
const Kind = "identity.audit_event.v1"

// DrainBatch is how many entries one drain pass takes. Small because the steady state is zero or one: an entry is written by an
// operator action and delivered by that same request, and the sweep exists for the ones a crash or a database blip left behind.
const DrainBatch = 100

// auditEntryV1 is the ON-DISK shape of an outbox payload, with explicit tags, and it is deliberately not identityapi.AuditEvent.
//
// The entry outlives the process that wrote it and may be read by a replica running different code, so its encoding is a format
// this package owns rather than whatever field names AuditEvent happens to have today. Marshalling the domain type directly would
// make a field rename in another context silently change a persisted format, which is the kind of coupling a durable encoding must
// not have. The tags are what Kind names: change either and the kind changes with it.
//
// TraceID is carried EXPLICITLY, which review corrected and which matters more than it looks. The recorder falls back to the trace
// on the context of the Record call when the event carries none, and the drain's context is whichever caller happened to run it: a
// request that makes one change also drains entries other requests left behind, so an empty trace here would stamp THIS
// request's trace onto somebody else's audit row. Carrying the writer's own trace, or none at all, is the only honest answer, and
// the drain detaches its context so the fallback cannot fire.
//
// RemoteAddr IS carried, as of the response context adopting this outbox (issue #1070): a containment change records the address the
// operator made it from, and delivering that row without the address would make the outbox a downgrade from recording it afterwards.
// The field is optional and the kind is unchanged, deliberately. Adding it is a compatible extension in the direction that matters: an
// entry a newer replica wrote and an older replica delivers loses only the address, never the row, and the exposure is one entry whose
// writer could not deliver it during a rolling deploy. A new kind would instead strand every entry already written as v1, because a
// drain leaves what it does not recognise.
type auditEntryV1 struct {
	ActorID    string         `json:"actor_id"`
	TraceID    string         `json:"trace_id,omitempty"`
	RemoteAddr string         `json:"remote_addr,omitempty"`
	ActorType  string         `json:"actor_type"`
	ActorLabel string         `json:"actor_label"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Payload    map[string]any `json:"payload,omitempty"`
}

// Encode turns an audit event into an outbox entry.
//
// The encoding is this package's, not the storing context's. That is why rulecontent's outbox column is opaque: it commits the bytes
// with the change without learning what an audit event is, which is the boundary ADR-0021 sets and which a shared struct would cross.
func Encode(e identityapi.AuditEvent) (Entry, error) {
	payload, err := json.Marshal(auditEntryV1{
		ActorID:    e.Actor.ID,
		TraceID:    e.TraceID,
		RemoteAddr: e.RemoteAddr,
		ActorType:  string(e.Actor.Type),
		ActorLabel: e.Actor.Label,
		Action:     string(e.Action),
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		Payload:    e.Payload,
	})
	if err != nil {
		return Entry{}, fmt.Errorf("encode audit outbox entry: %w", err)
	}
	return Entry{Kind: Kind, Payload: payload}, nil
}

// Decode is Encode's inverse.
func Decode(payload []byte) (identityapi.AuditEvent, error) {
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
		TraceID:    stored.TraceID,
		RemoteAddr: stored.RemoteAddr,
		Action:     identityapi.AuditAction(stored.Action),
		TargetType: stored.TargetType,
		TargetID:   stored.TargetID,
		Payload:    stored.Payload,
	}, nil
}

// Drain turns committed outbox entries into audit rows.
//
// Delivery is at-least-once and the audit log tolerates it, because an entry is deleted only after the recorder reports success:
// a crash between the two redelivers, which duplicates a row rather than losing one. That is the right direction for an
// append-only trail, where a duplicate is visible and a gap is not.
type Drain struct {
	outbox  Outbox
	audit   identityapi.AuditRecorder
	subject string
	logger  *slog.Logger
}

// NewDrain builds a drain. Every collaborator is required, for the same reason the services require their recorder: a drain with a
// missing piece is a wiring in which every change loses its audit row, silently. subject names what the entries record ("rule
// content", "detection config") in the drain's log lines.
func NewDrain(outbox Outbox, audit identityapi.AuditRecorder, subject string, logger *slog.Logger) (*Drain, error) {
	if outbox == nil || audit == nil {
		return nil, fmt.Errorf("%s audit drain: an outbox and an audit recorder are both required", subject)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Drain{outbox: outbox, audit: audit, subject: subject, logger: logger}, nil
}

// Drain delivers the pending entries, oldest first, and returns how many it delivered.
//
// Stops at the FIRST failure rather than skipping past it, and deletes only what it delivered. Order is the reason: the entries
// are a sequence of changes to what a fleet detects, and delivering a later one over a failed earlier one would produce a trail
// whose order disagrees with the changes it records. A stalled entry is retried on the next pass.
func (d *Drain) Drain(ctx context.Context) (int, error) {
	// Detached from the caller's trace, deliberately. The recorder falls back to the trace on this context when an event carries
	// none, and a request that makes one change also drains entries other requests left behind: without this, request B would
	// stamp its own trace onto request A's audit row. Cancellation still propagates, so a shutting-down caller stops promptly.
	ctx = trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	pending, err := d.outbox.PendingAuditEntries(ctx, DrainBatch)
	if err != nil {
		return 0, err
	}
	delivered := make([]int64, 0, len(pending))
	var stopErr error
	for _, entry := range pending {
		// An entry this replica cannot READ is skipped, not stopped on, and never deleted. Review caught the difference: stopping
		// meant one entry a replica could not decode stalled every audit row written after it, indefinitely, which trades a
		// delayed row for a stalled log. Skipping costs ordering for the entries around it and nothing else, and the entry stays
		// for a replica that can read it. Ordering is best-effort under version skew; delivery is not.
		if entry.Kind != Kind {
			// During a rolling deployment the writer may be a version ahead. Deleting what it wrote would lose the audit row it
			// was careful to make durable, so this waits for the replica that understands it.
			d.logger.WarnContext(ctx, "audit outbox entry has an unknown encoding; leaving it for a newer replica",
				"subject", d.subject, "id", entry.ID, "kind", entry.Kind)
			continue
		}
		e, err := Decode(entry.Payload)
		if err != nil {
			// Louder, because an entry that cannot be decoded by the version that wrote its kind is a defect rather than skew.
			// Still not deleted: dropping it would hide the defect by removing its evidence.
			d.logger.ErrorContext(ctx, "audit outbox entry could not be decoded; leaving it in the outbox",
				"subject", d.subject, "id", entry.ID, "err", err)
			stopErr = fmt.Errorf("decode audit outbox entry %d: %w", entry.ID, err)
			continue
		}
		// A recorder failure DOES stop the pass, and that asymmetry is deliberate. The two skips above are about one entry this
		// replica cannot read; this is the audit store being unavailable, which the next entry would hit too. Continuing would
		// turn one outage into a burst of failed writes and deliver later entries ahead of earlier ones for no gain.
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
			d.logger.ErrorContext(ctx, "delivered audit outbox entries but could not clear them; they will redeliver",
				"subject", d.subject, "count", len(delivered), "err", err)
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
func (d *Drain) SweepLoop(ctx context.Context, interval time.Duration) {
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
				d.logger.ErrorContext(ctx, "sweeping audit outbox entries", "subject", d.subject, "err", err)
			}
			if delivered > 0 {
				// Worth a line: reaching here means a request committed a change whose audit row it could not write, which is
				// the condition the outbox exists for and which nothing else would report.
				d.logger.InfoContext(ctx, "delivered audit outbox entries a request had left behind",
					"subject", d.subject, "count", delivered)
			}
		}
	}
}
