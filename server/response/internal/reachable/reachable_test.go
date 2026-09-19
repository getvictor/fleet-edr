package reachable_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/auditoutbox"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
	"github.com/fleetdm/edr/server/response/internal/mysql"
	"github.com/fleetdm/edr/server/response/internal/reachable"
	"github.com/fleetdm/edr/server/response/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

var operator = identityapi.PrincipalRef{ID: "user:7", Type: "user", Label: "ir@example.com"}

// recordingAudit keeps every audit event the drain delivers.
type recordingAudit struct {
	mu     sync.Mutex
	events []identityapi.AuditEvent
}

func (r *recordingAudit) Record(_ context.Context, e identityapi.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recordingAudit) recorded() []identityapi.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]identityapi.AuditEvent(nil), r.events...)
}

type fixture struct {
	svc   *reachable.Service
	store *reachable.Store
	audit *recordingAudit
	drain *auditoutbox.Drain
	db    *sqlx.DB
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	audit := &recordingAudit{}
	outbox := auditoutbox.NewStore(db, mysql.AuditOutboxTable)
	drain, err := auditoutbox.NewDrain(outbox, audit, "response actions", nil)
	require.NoError(t, err)
	store := reachable.NewStore(db, outbox)
	return &fixture{svc: reachable.NewService(store, drain), store: store, audit: audit, drain: drain, db: db}
}

// deliver turns whatever is in the outbox into audit rows, which the sweep does in production.
func (f *fixture) deliver(t *testing.T) []identityapi.AuditEvent {
	t.Helper()
	_, err := f.drain.Drain(t.Context())
	require.NoError(t, err)
	return f.audit.recorded()
}

// spec:server-host-containment/operators-choose-what-a-contained-host-can-still-reach/the-set-starts-empty-and-is-replaced-whole
func TestADeploymentStartsWithNothingExtraReachable(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	set, err := f.svc.Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(0), set.Version, "version 0 is the seeded set, which no host has to be told about")
	assert.Empty(t, set.Addresses)
	// An EMPTY list, not a missing one. assert.Empty passes for nil too, and nil is what would reach a reader as `"addresses":null`,
	// turning "no destination is reachable" into "this field was not reported".
	encoded, err := json.Marshal(set)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"addresses":[]`)
	assert.Nil(t, set.UpdatedAt, "nobody has changed it, so there is no change time to report")
}

// spec:server-host-containment/operators-choose-what-a-contained-host-can-still-reach/the-set-starts-empty-and-is-replaced-whole
func TestReplacingTheSetStoresItWholeAtTheNextVersion(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	next, err := f.svc.Replace(t.Context(), operator, "203.0.113.9", []api.ReachableAddress{
		{CIDR: "192.0.2.7", Port: 443, Transport: api.TransportTCP, Note: "MDM server"},
		{CIDR: "10.0.0.0/8", Note: "corporate"},
	}, "keeping the MDM server reachable during the investigation", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), next.Version)
	assert.Equal(t, operator.ID, next.UpdatedBy)
	require.NotNil(t, next.UpdatedAt)

	// Read back through a fresh Get, not from the return value: the point is what a later request and a host's command will see.
	stored, err := f.svc.Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, next.Version, stored.Version)
	assert.Equal(t, []api.ReachableAddress{
		{CIDR: "192.0.2.7/32", Port: 443, Transport: api.TransportTCP, Note: "MDM server"},
		{CIDR: "10.0.0.0/8", Note: "corporate"},
	}, stored.Addresses, "stored canonical, in the order the operator wrote them")

	// Replaced WHOLE: the second replacement is the whole new set, so what it leaves out is gone rather than merged.
	after, err := f.svc.Replace(t.Context(), operator, "203.0.113.9",
		[]api.ReachableAddress{{CIDR: "10.0.0.0/8", Note: "corporate"}}, "the MDM work is done", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), after.Version)
	assert.Equal(t, []api.ReachableAddress{{CIDR: "10.0.0.0/8", Note: "corporate"}}, after.Addresses)
}

// A change to what every contained host can reach is audited with its reason, like the containment it weakens.
//
// spec:server-host-containment/operators-choose-what-a-contained-host-can-still-reach/widening-the-set-is-audited-with-its-reason
func TestAReplacementIsAuditedWithWhatChanged(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, err := f.svc.Replace(t.Context(), operator, "203.0.113.9", []api.ReachableAddress{
		{CIDR: "192.0.2.7", Port: 443, Transport: api.TransportTCP, Note: "MDM server"},
	}, "initial", nil)
	require.NoError(t, err)
	_, err = f.svc.Replace(t.Context(), operator, "203.0.113.9", []api.ReachableAddress{
		{CIDR: "198.51.100.5", Note: "forensic share"},
	}, "swapping the MDM server for the collection share", nil)
	require.NoError(t, err)

	events := f.deliver(t)
	require.Len(t, events, 2)
	latest := events[1]
	assert.Equal(t, identityapi.AuditContainmentReachableUpdate, latest.Action)
	assert.Equal(t, operator, latest.Actor)
	assert.Equal(t, "containment_config", latest.TargetType)
	assert.Equal(t, "swapping the MDM server for the collection share", latest.Payload["reason"])
	// What changed, not only where it ended up: a reviewer reading the second entry can see the MDM server left without
	// diffing it against the first.
	// Structured, with the operator's own name for each destination: "the MDM server" is what a reviewer looks for, and an address
	// is what they would otherwise have to recognise. Fields rather than a rendered sentence, so a note cannot forge a delimiter
	// and make one change read as another.
	assert.Equal(t, []any{map[string]any{"cidr": "198.51.100.5/32", "note": "forensic share"}}, latest.Payload["added"])
	assert.Equal(t, []any{map[string]any{
		"cidr": "192.0.2.7/32", "port": float64(443), "transport": "tcp", "note": "MDM server",
	}}, latest.Payload["removed"])
}

// A note edited on an address that was already there is not that address arriving and leaving again.
func TestEditingANoteIsNotReportedAsAChangeOfDestination(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	_, err := f.svc.Replace(t.Context(), operator, "", []api.ReachableAddress{{CIDR: "192.0.2.7", Note: "MDM"}}, "initial", nil)
	require.NoError(t, err)
	_, err = f.svc.Replace(t.Context(), operator, "",
		[]api.ReachableAddress{{CIDR: "192.0.2.7", Note: "MDM server (Jamf)"}}, "clearer label", nil)
	require.NoError(t, err)

	events := f.deliver(t)
	require.Len(t, events, 2)
	assert.NotContains(t, events[1].Payload, "added", "the destination did not arrive")
	assert.NotContains(t, events[1].Payload, "removed", "nor did it leave")
	// It is still a change, and the trail says which name became which. Recording nothing would leave a rename invisible, and the
	// note is how this trail identifies a destination at all.
	assert.Equal(t, []any{map[string]any{
		"from": map[string]any{"cidr": "192.0.2.7/32", "note": "MDM"},
		"to":   map[string]any{"cidr": "192.0.2.7/32", "note": "MDM server (Jamf)"},
	}}, events[1].Payload["renamed"])
	// InDelta with no tolerance: the count arrives as a JSON number, so it is a float64 and testifylint refuses Equal on one.
	assert.InDelta(t, 1, events[1].Payload["count"], 0, "the set is still one address")
}

// spec:server-host-containment/operators-choose-what-a-contained-host-can-still-reach/widening-the-set-is-audited-with-its-reason
func TestAReplacementWithoutAReasonIsRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, reason := range []string{"", "   ", "\t\n"} {
		_, err := f.svc.Replace(t.Context(), operator, "", []api.ReachableAddress{{CIDR: "192.0.2.7"}}, reason, nil)
		require.ErrorIs(t, err, api.ErrReachableReasonRequired)
	}
	// Refused means nothing was stored, rather than stored without a reason.
	set, err := f.svc.Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(0), set.Version)
	assert.Empty(t, f.audit.recorded())
}

// An invalid entry leaves the stored set alone. The whole replacement is one decision: a responder who asked for four destinations
// and silently got three would find out during an incident.
func TestARefusedSetChangesNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, err := f.svc.Replace(t.Context(), operator, "", []api.ReachableAddress{{CIDR: "192.0.2.7", Note: "MDM"}}, "initial", nil)
	require.NoError(t, err)

	_, err = f.svc.Replace(t.Context(), operator, "", []api.ReachableAddress{
		{CIDR: "198.51.100.5", Note: "forensic share"},
		{CIDR: "0.0.0.0/0", Note: "everything"},
	}, "adding the share", nil)
	require.ErrorIs(t, err, api.ErrReachableTooBroad)

	set, err := f.svc.Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(1), set.Version, "the version did not move")
	assert.Equal(t, []api.ReachableAddress{{CIDR: "192.0.2.7/32", Note: "MDM"}}, set.Addresses,
		"nor did the valid entry in the refused set arrive")
}

// spec:server-host-containment/operators-choose-what-a-contained-host-can-still-reach/two-operators-editing-at-once-are-told
func TestAnEditAgainstAVersionSomebodyElseMovedIsRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	read, err := f.svc.Get(t.Context())
	require.NoError(t, err)

	// Somebody else saves first, against the version both operators read.
	_, err = f.svc.Replace(t.Context(), operator, "", []api.ReachableAddress{{CIDR: "198.51.100.5"}}, "theirs", &read.Version)
	require.NoError(t, err)

	_, err = f.svc.Replace(t.Context(), operator, "", []api.ReachableAddress{{CIDR: "192.0.2.7"}}, "mine", &read.Version)
	require.ErrorIs(t, err, api.ErrReachableVersionConflict)

	// Theirs stands: the refusal did not apply this operator's edit over a change they never saw.
	set, err := f.svc.Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []api.ReachableAddress{{CIDR: "198.51.100.5/32"}}, set.Addresses)

	// Without an expected version the caller is asking for the set whatever it holds, which is what a scripted caller does.
	_, err = f.svc.Replace(t.Context(), operator, "", []api.ReachableAddress{{CIDR: "192.0.2.7"}}, "mine, again", nil)
	require.NoError(t, err)
}

// Each replacement gets a strictly later update time than the one before, from the database's clock. A host orders sets by version
// or by that time, so a later version stamped with an earlier time would let an out-of-order delivery put the older set back.
func TestEachReplacementIsStampedAfterTheOneBefore(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	var previous *api.ReachableSet
	for i := range 5 {
		set, err := f.svc.Replace(t.Context(), operator, "",
			[]api.ReachableAddress{{CIDR: "192.0.2.7", Port: 443 + i}}, "step", nil)
		require.NoError(t, err)
		require.NotNil(t, set.UpdatedAt)
		if previous != nil {
			assert.Equal(t, previous.Version+1, set.Version)
			assert.True(t, set.UpdatedAt.After(*previous.UpdatedAt),
				"version %d is stamped %v, not after version %d's %v", set.Version, set.UpdatedAt, previous.Version,
				previous.UpdatedAt)
		}
		previous = &set
	}
}

// A note is operator text, and the audit trail is the record of who widened containment, so the two must not be able to impersonate
// each other. An earlier version rendered entries into sentences like "10.0.0.0/8 (corporate) -> ..."; a note carrying that
// delimiter, a bracket or a newline could then make one change read as another to anyone scanning the trail.
//
// The fix is structural rather than escaping: entries are carried as fields, so there is no format to forge. This pins that, using a
// note built out of exactly the pieces the old rendering used as syntax.
//
// spec:server-host-containment/operators-choose-what-a-contained-host-can-still-reach/widening-the-set-is-audited-with-its-reason
func TestAnAdversarialNoteCannotForgeAnAuditEntry(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	const forged = ") -> 198.51.100.5/32 (innocent\nremoved: 10.0.0.0/8 (corporate)"

	_, err := f.svc.Replace(t.Context(), operator, "",
		[]api.ReachableAddress{{CIDR: "192.0.2.7", Note: forged}}, "adding one address", nil)
	require.NoError(t, err)

	events := f.deliver(t)
	require.Len(t, events, 1)
	added, ok := events[0].Payload["added"].([]any)
	require.True(t, ok, "added is a list of entries, not a rendered string")
	require.Len(t, added, 1, "one address was added, whatever its note says")

	entry, ok := added[0].(map[string]any)
	require.True(t, ok, "each entry carries its own fields, so a note cannot be read as another entry's")
	assert.Equal(t, "192.0.2.7/32", entry["cidr"])
	// The note is kept verbatim, in its own field, where it is text and not syntax.
	assert.Equal(t, forged, entry["note"])
	assert.NotContains(t, events[0].Payload, "removed", "nothing was removed, whatever the note spells")
}

// A replacement whose audit entry cannot be built must store nothing. The set and the record of who changed it are one commit or
// neither, and this is the half that proves the "neither": the row is updated BEFORE the audit callback runs, so without the
// rollback the set would move with nobody accountable for it.
//
// Driven through the store rather than the service, because the service always builds an entry successfully; the failure this
// covers belongs to the transaction, which is shared with the watched-path set (issue #1109).
func TestASetWhoseAuditCannotBeBuiltIsNotStored(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, err := f.svc.Replace(t.Context(), operator, "", []api.ReachableAddress{{CIDR: "192.0.2.7", Note: "MDM"}}, "initial", nil)
	require.NoError(t, err)

	refuse := errors.New("the audit entry could not be built")
	_, _, err = f.store.Replace(t.Context(), []api.ReachableAddress{{CIDR: "198.51.100.5"}}, "user:7", nil,
		func(_, _ api.ReachableSet) (auditoutbox.Entry, error) { return auditoutbox.Entry{}, refuse })
	require.ErrorIs(t, err, refuse)

	set, err := f.svc.Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(1), set.Version, "the version must not move when the change was rolled back")
	assert.Equal(t, []api.ReachableAddress{{CIDR: "192.0.2.7/32", Note: "MDM"}}, set.Addresses,
		"nor may the abandoned replacement's addresses be stored")
}

// Two operators saving edits of the same version must not both succeed. This is the row lock's own test, and the lock is the
// subtlest thing the shared store owns (issue #1109): without it both replacements read the same version, both find their
// expected version intact, and the second silently overwrites the first at a version nobody was told about.
//
// The first replacement is held open INSIDE its transaction, in the audit callback, which runs after the row is locked and
// updated and before the commit. That is what makes the outcome deterministic rather than a race the test usually wins: while it
// is held, the second replacement is at its own locking read.
//
// spec:server-host-containment/operators-choose-what-a-contained-host-can-still-reach/two-operators-editing-at-once-are-told
func TestTwoOperatorsSavingTheSameVersionCannotBothSucceed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, err := f.svc.Replace(t.Context(), operator, "", []api.ReachableAddress{{CIDR: "192.0.2.7", Note: "MDM"}}, "initial", nil)
	require.NoError(t, err)
	from := int64(1)

	held, holding := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		_, _, rerr := f.store.Replace(t.Context(), []api.ReachableAddress{{CIDR: "198.51.100.5"}}, "user:7", &from,
			func(_, _ api.ReachableSet) (auditoutbox.Entry, error) {
				close(holding)
				<-held // the row is locked and updated; the transaction is open
				return auditoutbox.Entry{Kind: "response.audit.v1", Payload: []byte(`{}`)}, nil
			})
		first <- rerr
	}()

	select {
	case <-holding:
	case <-time.After(10 * time.Second):
		close(held)
		t.Fatal("the first replacement never reached its audit callback")
	}

	second := make(chan error, 1)
	go func() {
		_, _, rerr := f.store.Replace(t.Context(), []api.ReachableAddress{{CIDR: "203.0.113.9"}}, "user:9", &from,
			func(_, _ api.ReachableSet) (auditoutbox.Entry, error) {
				return auditoutbox.Entry{Kind: "response.audit.v1", Payload: []byte(`{}`)}, nil
			})
		second <- rerr
	}()
	// Long enough that a second replacement which was NOT blocked would have finished its own read and check by now.
	time.Sleep(250 * time.Millisecond)
	close(held)

	require.NoError(t, <-first, "the operator who took the lock first must succeed")
	require.ErrorIs(t, <-second, api.ErrReachableVersionConflict,
		"the second saved against a version that had moved, and must be told rather than overwrite it")

	set, err := f.svc.Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(2), set.Version, "exactly one replacement landed")
	// As written: the store stores what it is given, and it is the service that normalizes a bare address to its prefix.
	assert.Equal(t, []api.ReachableAddress{{CIDR: "198.51.100.5"}}, set.Addresses, "and it is the first operator's")
}
