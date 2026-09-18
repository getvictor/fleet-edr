package reachable_test

import (
	"context"
	"sync"
	"testing"

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
	assert.Equal(t, []any{"198.51.100.5/32"}, latest.Payload["added"])
	assert.Equal(t, []any{"192.0.2.7/32:443/tcp"}, latest.Payload["removed"])
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
	assert.NotContains(t, events[1].Payload, "added")
	assert.NotContains(t, events[1].Payload, "removed")
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
