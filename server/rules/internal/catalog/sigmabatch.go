package catalog

import (
	"context"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
)

// sigmaScopeKey names this package's slot in api.BatchScope. Every store and every read of it is in this file, which is what makes
// the `any` the scope carries safe: the assertion is between two lines of one package rather than across a boundary.
const sigmaScopeKey = "catalog.sigma"

// adaptedEvent is one event decoded once for the whole batch, together with the lookups a rule may need from it.
//
// The decode is shared because it is pure and expensive. The lookups are shared because they hit the database, which is far more
// expensive still: eleven of the corpus rules read ParentImage, and without sharing each would issue its own pair of graph reads
// for the same event. What is NOT shared is the resolver ERROR, which each rule gets its own copy of through
// sigmabind.Event.WithResolver, so a rule that never read the field does not lose its batch to another rule's failed lookup.
type adaptedEvent struct {
	core *sigmabind.Event
	// image resolves whichever image the taxonomy supplies for this event type: an exec resolves its PARENT's, an open resolves
	// its own subject's. Memoized, so the graph is read at most once per event per batch however many rules ask.
	image func(context.Context) (string, error)
	// subject resolves the process a finding names, which EVERY converted rule needs: each one attaches its finding to a process
	// row. Memoized for the same reason as image. On an open it is the SAME lookup image reads through, so a finding cannot name a
	// different process than the one the detection matched; on an exec the two are different rows, the parent's and the subject's.
	subject func(context.Context) (*api.Process, error)
	// pid is the process the event is about, read from the one decode above rather than from a second pass over the payload.
	pid    int
	hasPID bool
	// err records a decode failure, memoized so N rules do not each re-attempt a deterministic failure.
	err error
}

// sigmaBatch is the per-batch memo of decoded events, keyed by event id.
//
// Event id is the right key and index into the batch is not: the engine scopes the batch per rule by platform, so two rules can be
// handed slices of different lengths over the same events. Ids are unique within a batch by construction, because the batch is
// claimed from the events table where event_id is the primary key.
type sigmaBatch struct {
	events map[string]*adaptedEvent
}

// sigmaEventsFor returns the batch memo, creating it on the first ask of this batch.
func sigmaEventsFor(scope *api.BatchScope) *sigmaBatch {
	return scope.Derive(sigmaScopeKey, func() any {
		return &sigmaBatch{events: map[string]*adaptedEvent{}}
	}).(*sigmaBatch)
}

// adapt returns the shared adaptation of one event, building it on first ask.
//
// The build function is the caller's, because which lookups an event needs is a property of its type and the rule package knows it.
// It runs at most once per event per batch.
func (b *sigmaBatch) adapt(evt api.Event, build func() *adaptedEvent) *adaptedEvent {
	if existing, ok := b.events[evt.EventID]; ok {
		return existing
	}
	built := build()
	b.events[evt.EventID] = built
	return built
}

// sigmaView is one rule's view of a shared adapted event.
type sigmaView struct {
	// Event carries the shared decoded fields with a resolver error slot of this rule's own.
	Event *sigmabind.Event
	// Subject resolves the process a finding names, through the memo shared with every other rule in this batch.
	Subject func() (*api.Process, error)
	// PID is the process the event is about.
	PID int
}

// matchSubject runs detection against this rule's view and returns the process a finding names. A nil process with a nil error
// means no finding: the detection declined (noteUnmatched records an abandon if the subject was missing) or it matched a subject that
// never materialized (subjectOrAbandon records that one).
//
// The resolver error is checked before the verdict is trusted, for every rule, including one whose detection reads no graph field
// today. A failed read leaves the field absent, which reads as a decline, so skipping the check would turn a retryable miss into a
// silently lost detection the day the pack file starts reading that field, and the pack file can do that without the Go code
// changing.
func (v *sigmaView) matchSubject(scope *api.BatchScope, detection *sigma.Rule, ruleID string) (*api.Process, error) {
	matched := detection.Matches(v.Event)
	if err := v.Event.ResolveErr(); err != nil {
		return nil, err
	}
	if !matched {
		v.noteUnmatched(scope, ruleID)
		return nil, nil
	}
	return v.subjectOrAbandon(scope, ruleID)
}

// subjectOrAbandon is Subject for a detection that MATCHED: it returns the process the finding names, and when that process never
// materialized (nil past the grace; a young miss is the retryable error instead) records the abandon against ruleID. The finding is
// dropped there, so without the count a match the rule could not report is indistinguishable from no match (issue #1169).
func (v *sigmaView) subjectOrAbandon(scope *api.BatchScope, ruleID string) (*api.Process, error) {
	proc, err := v.Subject()
	if err == nil && proc == nil {
		scope.RecordMaterializationAbandoned(ruleID, v.PID)
	}
	return proc, err
}

// noteUnmatched records an abandon for a detection that did NOT match because the subject's record was missing. The only field a
// detection reads from the graph is the one the adapter resolves (Image on a file event, ParentImage on an exec), and both are read
// through the subject: a file event's Image IS the subject's path, and an exec's parent is found from the subject's row. So a rule
// that read that field while the subject was missing decided without it, and one that never read it did not depend on the process
// and is not charged. A present subject whose PARENT is missing is not an abandon either: a parent can predate the capture. The
// subject was already resolved by the read, through the shared memo, so this reads nothing new.
//
// Every Sigma-backed rule calls this on a non-match, including rules whose current detection never reads a graph field. The
// detection is authored in the pack file and can start reading one without the Go code changing, and the rule's AbandonCounter
// declaration has to stay true when it does.
func (v *sigmaView) noteUnmatched(scope *api.BatchScope, ruleID string) {
	if !v.Event.ImageResolved() {
		return
	}
	if proc, err := v.Subject(); err == nil && proc == nil {
		scope.RecordMaterializationAbandoned(ruleID, v.PID)
	}
}

// sigmaEvent returns this rule's view of the shared adaptation of one event, or nil when the event cannot be adapted at all.
//
// Every Sigma-backed rule goes through here rather than constructing its own adapter, and that is what turns the two decodes per
// rule per event (one for the pid, one inside the adapter) into one decode per event however many rules look at it. The graph
// lookups are shared on the same terms; only the resolver ERROR is per rule, so a rule that never read the image does not lose its
// batch to another rule's failed lookup.
//
// It returns NO error, and that is the contract rather than an omission. The two ways an event fails to adapt, a payload that does
// not decode and one carrying no pid, both mean the event is malformed rather than uninteresting, and every rule answers a
// malformed event the same way: skip it. Reporting them as errors would let one bad event discard the findings a rule had already
// collected from the rest of the batch, which is the behaviour each of these rules was written to avoid.
func sigmaEvent(ctx context.Context, scope *api.BatchScope, evt api.Event, gr api.GraphReader) *sigmaView {
	shared := sigmaEventsFor(scope).adapt(evt, func() *adaptedEvent { return buildAdapted(evt, gr) })
	if shared.err != nil || !shared.hasPID {
		return nil
	}
	// Bound to THIS rule's context, not the one that first saw the event. The lookups are lazy, so whichever rule triggers one
	// runs it, and running it under an earlier rule's already-ended span would attribute the MySQL query (instrumented through
	// otelsql) to a rule that did not ask for it.
	return &sigmaView{
		Event:   shared.core.WithResolver(func() (string, error) { return shared.image(ctx) }),
		Subject: func() (*api.Process, error) { return shared.subject(ctx) },
		PID:     shared.pid,
	}
}

// buildAdapted decodes one event and binds the memoized lookups its type calls for.
//
// It takes no context on purpose: nothing here reads the graph. The lookups it binds take their context when they are invoked, so
// the rule that triggers one is the rule the query is traced under.
//
// An exec resolves its PARENT's image, at the child's fork time; an open resolves the image of the process that did the opening and
// also hands that process back, so the finding names the one the detection matched. Both are deferred, because a detection reaches
// the graph only after the far cheaper field tests have already narrowed the events, and Sigma's conditions short-circuit.
func buildAdapted(evt api.Event, gr api.GraphReader) *adaptedEvent {
	core, err := sigmabind.NewEvent(evt)
	if err != nil {
		return &adaptedEvent{err: err}
	}
	pid, ok := core.SubjectPID()
	if !ok {
		// A mapped event with no pid is malformed rather than uninteresting. Recorded rather than raised, so the rule decides:
		// one bad event must not discard the findings the rest of the batch produced.
		return &adaptedEvent{core: core}
	}

	// The image is read THROUGH the subject in both branches. On an open they resolve the same row, so a finding cannot name a
	// different process than the detection matched. On an exec the image is the parent's, found from the subject's row, so a young
	// subject is a retry there too rather than an absent ParentImage (issue #1169).
	subject := subjectProcessOf(evt, gr, pid)
	// A rename resolves the same way an open does: the acting process IS the subject, so Image and the finding's subject are
	// one row and a finding cannot name a process the detection did not match on.
	if evt.EventType == "open" || evt.EventType == "file_rename" || evt.EventType == "file_truncate" || evt.EventType == "file_delete" {
		return &adaptedEvent{core: core, pid: pid, hasPID: true, image: subjectImageOf(subject), subject: subject}
	}
	return &adaptedEvent{core: core, pid: pid, hasPID: true, image: parentImageOf(evt, gr, subject), subject: subject}
}

// Every Sigma-backed rule records its abandons through sigmaView (subjectOrAbandon and noteUnmatched), so each declares that it
// counts. Asserted here so a rule that stops satisfying the interface fails to compile rather than silently reporting "not measured".
var (
	_ api.AbandonCounter = (*CredentialKeychainDump)(nil)
	_ api.AbandonCounter = (*DyldInsert)(nil)
	_ api.AbandonCounter = (*ShellFromOffice)(nil)
	_ api.AbandonCounter = (*SudoersTamper)(nil)
	_ api.AbandonCounter = (*SudoersDestroyed)(nil)
	_ api.AbandonCounter = (*importedRule)(nil)
)
