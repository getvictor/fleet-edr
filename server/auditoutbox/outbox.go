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
// operator action, which asks for a pass at once, and what is left for the interval is what a crash or a database blip stranded.
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
	// wake carries a request from DeliverSoon to SweepLoop, one deep: a sweep reads the outbox when it runs, so two requests that
	// arrive together are answered by one pass (issue #1089).
	//
	// In-process and safe to lose, so it does not make the server stateful (ADR-0010). What has to survive is the entry, and that is
	// in the database before anything is signalled. A dropped signal, a replica that exits with one pending, or a signal raised where
	// no sweep is running costs the row the wait until the next interval; no peer replica needs to see it.
	wake chan struct{}
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
	return &Drain{outbox: outbox, audit: audit, subject: subject, logger: logger, wake: make(chan struct{}, 1)}, nil
}

// Drain delivers the pending entries, oldest first, and returns how many it delivered.
//
// Stops at the FIRST failure rather than skipping past it, and deletes only what it delivered. Order is the reason: the entries
// are a sequence of changes to what a fleet detects, and delivering a later one over a failed earlier one would produce a trail
// whose order disagrees with the changes it records. A stalled entry is retried on the next pass.
func (d *Drain) Drain(ctx context.Context) (int, error) {
	_, delivered, err := d.pass(ctx)
	return delivered, err
}

// pass is one drain, reporting how many entries it READ as well as how many it delivered. The two differ whenever an entry is
// skipped or a failure stops the loop, and the sweep needs the read count: a batch that came back full is what says the outbox may
// hold more, whether or not this replica could deliver all of it.
func (d *Drain) pass(ctx context.Context) (fetched, delivered int, err error) {
	// Detached from the caller's trace, deliberately. The recorder falls back to the trace on this context when an event carries
	// none, and a request that makes one change also drains entries other requests left behind: without this, request B would
	// stamp its own trace onto request A's audit row. Cancellation still propagates, so a shutting-down caller stops promptly.
	ctx = trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	pending, err := d.outbox.PendingAuditEntries(ctx, DrainBatch)
	if err != nil {
		return 0, 0, err
	}
	sent := make([]int64, 0, len(pending))
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
		sent = append(sent, entry.ID)
	}
	if len(sent) > 0 {
		if err := d.outbox.DeleteAuditEntries(ctx, sent); err != nil {
			// The rows were recorded and the entries were not removed, so the next pass records them again. At-least-once is
			// the guarantee, so this is a duplicate rather than a loss, and it is worth a line because a persistent failure here
			// would show up as a repeating audit row.
			d.logger.ErrorContext(ctx, "delivered audit outbox entries but could not clear them; they will redeliver",
				"subject", d.subject, "count", len(sent), "err", err)
			return len(pending), len(sent), err
		}
	}
	return len(pending), len(sent), stopErr
}

// DeliverSoon asks the sweep to deliver what the caller just committed, without waiting for it. Every caller runs it immediately
// after its transaction commits.
//
// It does NOT deliver on the caller's goroutine, and that is the point (issue #1089). Delivering there put a request behind up to
// DrainBatch audit-store writes before it could answer: in the steady state that is the one entry the request wrote and costs
// nothing, but after an audit-store outage the first requests back meet a backlog, and a slow store then delays a response whose
// change has already committed. For a destructive action that is worse than slow, because an operator who sees a timeout and retries
// has issued it twice.
//
// The request is one deep. A sweep reads the outbox when it runs, so callers arriving together are answered by one pass rather than
// queueing a pass each, and nothing blocks when the sweep is already busy.
//
// A nil Drain is the wiring with no audit recorder, which only non-production setups have. It says so rather than returning silently,
// because the entry then waits in the outbox and this is the only thing that would report a change with no audit row. It logs through
// the default logger, having no configured one of its own, which is acceptable for a path production does not take.
func (d *Drain) DeliverSoon(ctx context.Context) {
	if d == nil {
		slog.Default().WarnContext(ctx, "audit entry is committed but not delivered: no audit recorder is wired")
		return
	}
	d.request()
}

// request asks the sweep for a pass without waiting for one, and drops the request when one is already outstanding: a pass reads the
// outbox when it runs, so a second request would buy nothing a queued pass does not already cover.
func (d *Drain) request() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// DefaultSweepInterval is how often the sweep looks for entries no caller asked it to deliver.
//
// A minute rather than seconds. The steady state is an empty table: an operator action asks for a pass as soon as it commits, and
// what the interval finds is what a crash or a database blip stranded. Polling faster would buy latency on an audit row that is
// already durable, at the cost of a query per replica per interval against a table that is almost always empty.
const DefaultSweepInterval = time.Minute

// SweepLoop delivers committed entries until ctx is cancelled: the ones a caller has just asked for through DeliverSoon, and every
// interval whatever is left in the outbox regardless.
//
// The interval is not redundant now that callers signal. A signal is in-process, so it is lost by a replica that exits between the
// commit and the sweep, and it never reaches the replica that has to deliver an entry another one wrote. The interval is what makes
// delivery depend on the durable entry rather than on the signal arriving.
//
// This loop is what delivers a change's audit row, so a context that enqueues entries and never runs it writes none. Both bootstraps
// start it from their Run, unconditionally on having a recorder rather than on which routes are mounted.
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
		case <-d.wake:
			d.sweep(ctx, false)
		case <-ticker.C:
			d.sweep(ctx, true)
		}
	}
}

// sweep runs one pass and reports what it found, where onInterval separates the two reasons a pass runs.
//
// Entries an interval pass finds were not asked for by any caller on this replica: the request that wrote them died, or the signal
// went somewhere else. That is the condition the outbox exists for and nothing else reports it. Entries a requested pass finds are
// the steady state, one per operator action, and logging those would say only that the server is working.
func (d *Drain) sweep(ctx context.Context, onInterval bool) {
	fetched, delivered, err := d.pass(ctx)
	if err != nil {
		d.logger.ErrorContext(ctx, "sweeping audit outbox entries", "subject", d.subject, "err", err)
	}
	if onInterval && delivered > 0 {
		// What the interval pass delivered, and no more of a claim than that. A request can arrive while this pass is reading or
		// recording, and a request and the tick can be ready at the same moment, in which case the select may take either: this
		// pass cannot tell that nothing asked for these entries, so it does not say so.
		d.logger.InfoContext(ctx, "delivered audit outbox entries on the periodic sweep",
			"subject", d.subject, "count", delivered)
	}
	// A pass takes at most DrainBatch, and the callers whose entries it did not reach have already spent their one request on the
	// pass that just ran: without this, entry DrainBatch+1 of a burst would wait for the interval. So a pass that READ a full batch
	// asks for the next one itself, and the outbox is drained over as many passes as it takes.
	//
	// On what it read, not on what it delivered: a pass skips an entry written in an encoding this replica does not know, so one
	// such entry among a full batch would leave the count short and strand everything after it until the interval.
	//
	// Guarded two ways against sweeping in a tight loop over entries this replica cannot clear. A pass that failed is left to the
	// interval, because a failing store is the wrong thing to retry immediately. A pass that delivered nothing is too: a replica
	// meeting a full batch it cannot read would otherwise re-read the same entries forever, since a skipped entry is never deleted.
	// The cost of that guard is that a full batch of unreadable entries hides what is behind it from this replica until the replica
	// that understands them clears them, which is already true of any batch they fill.
	if err == nil && fetched == DrainBatch && delivered > 0 {
		d.logger.InfoContext(ctx, "audit outbox holds more than one pass delivers; sweeping again",
			"subject", d.subject, "count", delivered)
		d.request()
	}
}
