package containment_test

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/fleetdm/edr/server/auditoutbox"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
	"github.com/fleetdm/edr/server/response/internal/containment"
	"github.com/fleetdm/edr/server/response/internal/mysql"
	"github.com/fleetdm/edr/server/response/internal/service"
	"github.com/fleetdm/edr/server/response/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// recordingAudit keeps every audit event recorded, and refuses them while unavailable, as a store that is down does.
type recordingAudit struct {
	mu          sync.Mutex
	events      []identityapi.AuditEvent
	unavailable error
}

func (r *recordingAudit) Record(_ context.Context, e identityapi.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unavailable != nil {
		return r.unavailable
	}
	r.events = append(r.events, e)
	return nil
}

// goesDown makes every later Record fail; comesBack lets them through again.
func (r *recordingAudit) goesDown(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unavailable = err
}

func (r *recordingAudit) comesBack() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unavailable = nil
}

func (r *recordingAudit) recorded() []identityapi.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]identityapi.AuditEvent(nil), r.events...)
}

// fixture is a containment service and converger over an isolated database, with the real command store behind them.
type fixture struct {
	store     *containment.Store
	svc       *containment.Service
	converger *containment.Converger
	commands  *service.Service
	audit     *recordingAudit
	outbox    *auditoutbox.Store
	drain     *auditoutbox.Drain
	// db is the test's own handle, for asking the database what another connection can see.
	db *sqlx.DB
	// notified records the hosts the control gateway was told about, in order, after their transactions committed.
	notified *notifyRecorder
	// enrolled is each enrolled host's enrollment time.
	enrolled map[string]time.Time
	// sweeping starts the drain's sweep on the first test that reads audit rows, since delivery is no longer part of the change.
	sweeping sync.Once
}

var operator = identityapi.PrincipalRef{ID: "user:7", Type: "user", Label: "ir@example.com"}

// notifyRecorder captures the gateway notifications a change or a sweep makes, and what another connection could see of that host's
// commands at the moment each notification was made. The gateway reads the command from its own connection, so a notification sent
// before the transaction commits sends it looking for a row that is not there.
type notifyRecorder struct {
	mu      sync.Mutex
	hosts   []string
	visible []int
	db      *sqlx.DB
}

func (n *notifyRecorder) notify(hostID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.hosts = append(n.hosts, hostID)
	if n.db == nil {
		return
	}
	var count int
	if err := n.db.Get(&count,
		`SELECT COUNT(*) FROM commands WHERE host_id = ? AND command_type = ?`, hostID, api.CommandTypeSetNetworkContainment); err != nil {
		count = -1
	}
	n.visible = append(n.visible, count)
}

// commandsVisibleAtNotify is how many of the host's containment commands another connection could see at each notification.
func (n *notifyRecorder) commandsVisibleAtNotify() []int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]int(nil), n.visible...)
}

func (n *notifyRecorder) recorded() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.hosts...)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	f := &fixture{
		store: containment.NewStore(db), commands: service.New(mysql.NewStore(db), nil, nil), audit: &recordingAudit{},
		outbox: auditoutbox.NewStore(db, mysql.AuditOutboxTable), notified: &notifyRecorder{db: db}, db: db,
		enrolled: map[string]time.Time{"host-a": time.Now().Add(-time.Hour), "host-b": time.Now().Add(-time.Hour)},
	}
	isEnrolled := func(_ context.Context, hostID string) (bool, error) {
		_, ok := f.enrolled[hostID]
		return ok, nil
	}
	enrollments := func(context.Context) ([]api.HostEnrollment, error) {
		out := make([]api.HostEnrollment, 0, len(f.enrolled))
		for hostID, at := range f.enrolled {
			out = append(out, api.HostEnrollment{HostID: hostID, EnrolledAt: at})
		}
		return out, nil
	}
	drain, err := auditoutbox.NewDrain(f.outbox, f.audit, "host containment", nil)
	require.NoError(t, err)
	f.drain = drain
	f.svc = containment.NewService(f.store, isEnrolled, f.commands.QueueTx, f.notified.notify, f.commands.LatestOfType, f.outbox, f.drain)
	f.converger = containment.NewConverger(f.store, f.commands.QueueTx, f.notified.notify, enrollments,
		f.commands.LatestOfType, nil)
	return f
}

// containmentCommands returns a host's set_network_containment commands, oldest first.
func (f *fixture) containmentCommands(t *testing.T, hostID string) []api.Command {
	t.Helper()
	all, err := f.commands.ListForHost(t.Context(), hostID, "")
	require.NoError(t, err)
	var out []api.Command
	for _, c := range all {
		if c.CommandType == api.CommandTypeSetNetworkContainment {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b api.Command) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

// commandPayloadFor is the payload the service and the catch-up both queue, rebuilt here for the tests that drive the store directly.
func commandPayloadFor(state api.ContainmentState) []byte {
	payload, _ := json.Marshal(api.SetNetworkContainmentPayload{
		Version: state.Version, Epoch: state.Epoch, Contained: state.Contained,
	})
	return payload
}

func payloadOf(t *testing.T, cmd api.Command) api.SetNetworkContainmentPayload {
	t.Helper()
	var p api.SetNetworkContainmentPayload
	require.NoError(t, json.Unmarshal(cmd.Payload, &p))
	return p
}

// spec:server-host-containment/an-operator-contains-or-releases-a-host/an-operator-contains-a-host
// spec:server-host-containment/an-operator-contains-or-releases-a-host/a-release-is-recorded-the-same-way
// spec:server-host-containment/a-containment-change-commits-its-audit-entry/a-change-commits-with-its-audit-entry
//
// The audit assertions below read the rows the outbox delivered, so they are also what says the entry committed with the change:
// the recorder is only reached through a drain, and a drain only ever sees an entry the change's transaction wrote.
func TestSet_ContainsAndReleasesAHost(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	contain, err := f.svc.Set(t.Context(), operator, "203.0.113.5", "host-a", true, "  beaconing to a known C2  ")
	require.NoError(t, err)
	assert.True(t, contain.Changed)
	assert.Equal(t, "host-a", contain.State.HostID)
	assert.True(t, contain.State.Contained)
	assert.Equal(t, int64(1), contain.State.Version)
	assert.Equal(t, "beaconing to a known C2", contain.State.Reason, "the reason is recorded trimmed")
	assert.Equal(t, "user:7", contain.State.UpdatedBy)
	require.NotZero(t, contain.CommandID)
	cmds := f.containmentCommands(t, "host-a")
	require.Len(t, cmds, 1)
	assert.Equal(t, contain.CommandID, cmds[0].ID)
	assert.Equal(t, api.SetNetworkContainmentPayload{Version: 1, Epoch: contain.State.Epoch, Contained: true}, payloadOf(t, cmds[0]))

	release, err := f.svc.Set(t.Context(), operator, "203.0.113.5", "host-a", false, "reimaged")
	require.NoError(t, err)
	assert.True(t, release.Changed)
	assert.False(t, release.State.Contained)
	assert.Equal(t, int64(2), release.State.Version)
	assert.Greater(t, release.State.Epoch, contain.State.Epoch, "a later change has a later epoch")
	cmds = f.containmentCommands(t, "host-a")
	require.Len(t, cmds, 2)
	assert.Equal(t, api.SetNetworkContainmentPayload{Version: 2, Epoch: release.State.Epoch, Contained: false}, payloadOf(t, cmds[1]))

	events := f.auditRows(t, 2)
	assert.Equal(t, identityapi.AuditHostContain, events[0].Action)
	assert.Equal(t, identityapi.AuditHostRelease, events[1].Action)
	for i, e := range events {
		assert.Equal(t, operator, e.Actor)
		assert.Equal(t, "host", e.TargetType)
		assert.Equal(t, "host-a", e.TargetID)
		assert.Equal(t, "203.0.113.5", e.RemoteAddr)
		// EqualValues, not Equal: the entry commits as JSON and JSON has one number type, so a delivered payload's numbers arrive
		// as float64 whatever Go type was put in. The stored row is the same either way; the value is what the test is about.
		assert.EqualValues(t, i+1, e.Payload["version"])
	}
	assert.EqualValues(t, contain.State.Epoch, events[0].Payload["epoch"])
	assert.EqualValues(t, release.State.Epoch, events[1].Payload["epoch"])
	assert.Equal(t, "beaconing to a known C2", events[0].Payload["reason"])
	assert.EqualValues(t, contain.CommandID, events[0].Payload["command_id"])
}

// spec:server-host-containment/an-operator-contains-or-releases-a-host/a-change-without-a-reason-is-refused
// spec:server-host-containment/an-operator-contains-or-releases-a-host/a-reason-over-the-limit-is-refused
// spec:server-host-containment/an-operator-contains-or-releases-a-host/a-host-that-is-not-enrolled-cannot-be-contained
//
// Each refusal leaves no trace: no state is recorded for the host, no command is queued for it, and no audit event is written about it.
func TestSet_Refusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, hostID, reason string
		want                 error
	}{
		{"a blank reason", "host-a", " \t ", api.ErrContainmentReasonRequired},
		{"a reason over the limit", "host-a", strings.Repeat("é", api.MaxContainmentReasonLength+1), api.ErrContainmentReasonTooLong},
		{"a reason over the limit only with its whitespace", "host-a", strings.Repeat("é", api.MaxContainmentReasonLength) + " ",
			api.ErrContainmentReasonTooLong},
		{"a host with no active enrollment", "host-unknown", "suspicious", api.ErrContainmentHostNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			_, err := f.svc.Set(t.Context(), operator, "", tc.hostID, true, tc.reason)
			require.ErrorIs(t, err, tc.want)
			state, err := f.store.Get(t.Context(), tc.hostID)
			require.NoError(t, err)
			assert.Equal(t, api.ContainmentState{HostID: tc.hostID}, state)
			assert.Empty(t, f.containmentCommands(t, tc.hostID))
			assert.Empty(t, f.auditRows(t, 0))
		})
	}
	t.Run("a reason at the limit is accepted", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		_, err := f.svc.Set(t.Context(), operator, "", "host-a", true, strings.Repeat("é", api.MaxContainmentReasonLength))
		require.NoError(t, err)
	})
}

// spec:server-host-containment/an-operator-contains-or-releases-a-host/asking-for-the-current-state-changes-nothing
func TestSet_AskingForTheCurrentStateChangesNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	never, err := f.svc.Set(t.Context(), operator, "", "host-b", false, "not contained anyway")
	require.NoError(t, err)
	assert.Equal(t, api.ContainmentChange{State: api.ContainmentState{HostID: "host-b"}}, never, "releasing a host never contained")

	first, err := f.svc.Set(t.Context(), operator, "", "host-a", true, "first")
	require.NoError(t, err)
	again, err := f.svc.Set(t.Context(), operator, "", "host-a", true, "second")
	require.NoError(t, err)
	assert.False(t, again.Changed)
	assert.Zero(t, again.CommandID)
	assert.Equal(t, first.State, again.State, "the version, epoch and reason stay those of the change that made it")
	assert.Len(t, f.containmentCommands(t, "host-a"), 1)
	f.auditRows(t, 1)
	assert.Empty(t, f.containmentCommands(t, "host-b"))
}

// Concurrent first containments of one host serialize on its row: one changes it at version 1 and the others find it contained.
func TestSet_ConcurrentFirstContainmentsSerialize(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	const callers = 8
	results := make([]api.ContainmentChange, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			results[i], errs[i] = f.svc.Set(t.Context(), operator, "", "host-a", true, fmt.Sprintf("caller %d", i))
		})
	}
	wg.Wait()
	changed := 0
	for i := range callers {
		require.NoError(t, errs[i])
		assert.Equal(t, int64(1), results[i].State.Version)
		if results[i].Changed {
			changed++
		}
	}
	assert.Equal(t, 1, changed)
	assert.Len(t, f.containmentCommands(t, "host-a"), 1)
}

// spec:server-host-containment/the-containment-state-is-readable/a-contained-host-shows-its-state-and-delivery
// spec:server-host-containment/the-containment-state-is-readable/a-host-never-contained-has-no-state
func TestGet_StateAndDelivery(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	stale := []byte(`{"version":1,"epoch":1,"contained":true}`)
	_, err := f.commands.Insert(t.Context(), "host-b", api.CommandTypeSetNetworkContainment, stale)
	require.NoError(t, err)
	never, err := f.svc.Get(t.Context(), "host-b")
	require.NoError(t, err)
	assert.Equal(t, api.ContainmentState{HostID: "host-b"}, never, "a command queued by other means is not a delivery of a state")

	change, err := f.svc.Set(t.Context(), operator, "", "host-a", true, "suspicious")
	require.NoError(t, err)
	got, err := f.svc.Get(t.Context(), "host-a")
	require.NoError(t, err)
	assert.True(t, got.Contained)
	assert.Equal(t, int64(1), got.Version)
	assert.Equal(t, change.State.Epoch, got.Epoch)
	assert.Equal(t, "suspicious", got.Reason)
	assert.Equal(t, "user:7", got.UpdatedBy)
	require.NotNil(t, got.Delivery)
	assert.Equal(t, api.ContainmentDelivery{CommandID: change.CommandID, Status: api.StatusPending, Current: true}, *got.Delivery)

	// A command left over from an earlier state is the latest delivery but not a current one.
	_, err = f.commands.Insert(t.Context(), "host-a", api.CommandTypeSetNetworkContainment, stale)
	require.NoError(t, err)
	got, err = f.svc.Get(t.Context(), "host-a")
	require.NoError(t, err)
	require.NotNil(t, got.Delivery)
	assert.False(t, got.Delivery.Current)
}

// setStatus moves a command to status the way an agent or the expiry sweep does, and returns it.
func (f *fixture) setStatus(t *testing.T, id int64, status api.Status) api.Command {
	t.Helper()
	if status == api.StatusCompleted || status == api.StatusFailed {
		require.NoError(t, f.commands.UpdateStatus(t.Context(), api.UpdateStatusRequest{ID: id, HostID: "host-a", Status: api.StatusAcked}))
	}
	require.NoError(t, f.commands.UpdateStatus(t.Context(), api.UpdateStatusRequest{ID: id, HostID: "host-a", Status: status}))
	cmd, err := f.commands.Get(t.Context(), id)
	require.NoError(t, err)
	return cmd
}

// spec:server-host-containment/hosts-converge-on-their-containment-state/a-host-whose-command-expired-is-sent-the-state-again
// spec:server-host-containment/hosts-converge-on-their-containment-state/a-delivered-state-is-not-sent-again
// spec:server-host-containment/hosts-converge-on-their-containment-state/a-host-that-re-enrolled-is-sent-the-state-again
// spec:server-host-containment/hosts-converge-on-their-containment-state/a-failed-delivery-is-retried-after-six-hours
func TestConverge(t *testing.T) {
	t.Parallel()
	contained := func(t *testing.T) (*fixture, api.ContainmentChange) {
		t.Helper()
		f := newFixture(t)
		change, err := f.svc.Set(t.Context(), operator, "", "host-a", true, "suspicious")
		require.NoError(t, err)
		return f, change
	}
	queued := func(t *testing.T, f *fixture) int {
		t.Helper()
		n, err := f.converger.Converge(t.Context())
		require.NoError(t, err)
		return n
	}

	t.Run("a pending command for the current state is left alone", func(t *testing.T) {
		t.Parallel()
		f, _ := contained(t)
		assert.Zero(t, queued(t, f))
	})
	t.Run("an acknowledged command for the current state is left alone", func(t *testing.T) {
		t.Parallel()
		f, change := contained(t)
		f.setStatus(t, change.CommandID, api.StatusAcked)
		assert.Zero(t, queued(t, f))
	})
	t.Run("a completed command for the current state is not sent again", func(t *testing.T) {
		t.Parallel()
		f, change := contained(t)
		f.setStatus(t, change.CommandID, api.StatusCompleted)
		assert.Zero(t, queued(t, f))
	})
	t.Run("an expired command is sent again", func(t *testing.T) {
		t.Parallel()
		f, change := contained(t)
		f.setStatus(t, change.CommandID, api.StatusExpired)
		assert.Equal(t, 1, queued(t, f))
		cmds := f.containmentCommands(t, "host-a")
		require.Len(t, cmds, 2)
		assert.Equal(t, payloadOf(t, cmds[0]), payloadOf(t, cmds[1]), "the catch-up sends exactly what the change queued")
		assert.Zero(t, queued(t, f), "and not again while the new copy is pending")
	})
	t.Run("a cancelled command is sent again", func(t *testing.T) {
		t.Parallel()
		f, change := contained(t)
		f.setStatus(t, change.CommandID, api.StatusCancelled)
		assert.Equal(t, 1, queued(t, f))
	})
	t.Run("a host that re-enrolled after its command is sent the state again", func(t *testing.T) {
		t.Parallel()
		f, change := contained(t)
		f.setStatus(t, change.CommandID, api.StatusCompleted)
		f.enrolled["host-a"] = time.Now().Add(time.Hour)
		assert.Equal(t, 1, queued(t, f))
	})
	t.Run("a command for an earlier state is replaced", func(t *testing.T) {
		t.Parallel()
		f, _ := contained(t)
		stale := []byte(`{"version":1,"epoch":1,"contained":true}`)
		_, err := f.commands.Insert(t.Context(), "host-a", api.CommandTypeSetNetworkContainment, stale)
		require.NoError(t, err)
		assert.Equal(t, 1, queued(t, f))
	})
	t.Run("a failed command is retried after six hours and not before", func(t *testing.T) {
		t.Parallel()
		f, change := contained(t)
		failed := f.setStatus(t, change.CommandID, api.StatusFailed)
		require.NotNil(t, failed.CompletedAt)
		f.converger.SetNow(func() time.Time { return failed.CompletedAt.Add(6*time.Hour - time.Second) })
		assert.Zero(t, queued(t, f))
		f.converger.SetNow(func() time.Time { return failed.CompletedAt.Add(6 * time.Hour) })
		assert.Equal(t, 1, queued(t, f))
	})
	t.Run("a host that is not enrolled, or never contained, is sent nothing", func(t *testing.T) {
		t.Parallel()
		f, change := contained(t)
		f.setStatus(t, change.CommandID, api.StatusExpired)
		delete(f.enrolled, "host-a")
		assert.Zero(t, queued(t, f))
		assert.Empty(t, f.containmentCommands(t, "host-b"))
	})
	t.Run("command history is read only for enrolled hosts", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		for _, host := range []string{"host-a", "host-b"} {
			_, err := f.svc.Set(t.Context(), operator, "", host, true, "suspicious")
			require.NoError(t, err)
		}
		delete(f.enrolled, "host-b")
		var asked [][]string
		latest := func(ctx context.Context, commandType string, hostIDs []string) (map[string]api.Command, error) {
			asked = append(asked, hostIDs)
			return f.commands.LatestOfType(ctx, commandType, hostIDs)
		}
		enrollments := func(context.Context) ([]api.HostEnrollment, error) {
			return []api.HostEnrollment{{HostID: "host-a", EnrolledAt: f.enrolled["host-a"]}}, nil
		}
		_, err := containment.NewConverger(f.store, f.commands.QueueTx, f.notified.notify, enrollments, latest,
			nil).Converge(t.Context())
		require.NoError(t, err)
		assert.Equal(t, [][]string{{"host-a"}}, asked)
	})
}

// The control gateway is told after the transaction commits, not before: it reads the command through its own connection, so a
// notification sent inside the transaction sends it looking for a row that is not there yet (issue #1073).
func TestSet_TheGatewayIsToldOnlyOnceTheCommandIsVisible(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	change, err := f.svc.Set(t.Context(), operator, "", "host-a", true, "beaconing")
	require.NoError(t, err)
	require.True(t, change.Changed)

	assert.Equal(t, []string{"host-a"}, f.notified.recorded())
	assert.Equal(t, []int{1}, f.notified.commandsVisibleAtNotify(),
		"another connection can see the queued command when the gateway is told about it")
}

// Two changes to one host at the same moment queue their commands in the order of the states they carry. Before the command was
// queued inside the state's transaction, both could commit their states and then queue in the other order, leaving the newest command
// carrying the older state until the catch-up noticed (issue #1073).
// spec:server-host-containment/an-operator-contains-or-releases-a-host/commands-are-queued-in-the-order-of-the-states-they-carry
func TestSet_ConcurrentChangesQueueInVersionOrder(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// The contain runs first and holds its transaction open inside the queue callback, which is where the release would have to slip
	// through to queue out of order. reachedQueue fires when the release reaches the point of queuing its own command: while the
	// contain is held that must not happen, because the contain still holds the host's row. Queuing after the commit, as the code did
	// before this change, releases that row early and the release gets there at once, which is the ordering this test is about.
	holding := make(chan struct{})
	release := make(chan struct{})
	reachedQueue := make(chan struct{}, 1)
	slow := func(ctx context.Context, q sqlx.ExecerContext, state api.ContainmentState) (int64, error) {
		if state.Contained {
			close(holding)
			<-release
		} else {
			select {
			case reachedQueue <- struct{}{}:
			default:
			}
		}
		return f.commands.QueueTx(ctx, q, state.HostID, api.CommandTypeSetNetworkContainment, commandPayloadFor(state))
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _, _, err := f.store.Set(t.Context(), "host-a", true, "contain", "user:7", slow)
		assert.NoError(t, err)
	})

	<-holding
	wg.Go(func() {
		// Blocks on the host's row lock until the contain commits.
		_, _, _, err := f.store.Set(t.Context(), "host-a", false, "release", "user:7", slow)
		assert.NoError(t, err)
	})
	// The release must not get as far as queuing while the contain is held. Under the ordering this replaces it gets there in
	// milliseconds, so this wait fails fast on a regression rather than resting on a sleep being long enough.
	select {
	case <-reachedQueue:
		close(release)
		wg.Wait()
		t.Fatal("the release queued its command while the contain had not committed: the host's row was not held")
	case <-time.After(2 * time.Second):
	}
	close(release)
	wg.Wait()

	cmds := f.containmentCommands(t, "host-a")
	require.Len(t, cmds, 2)
	first := payloadOf(t, cmds[0])
	second := payloadOf(t, cmds[1])
	assert.Less(t, cmds[0].ID, cmds[1].ID)
	assert.Less(t, first.Version, second.Version, "the later state's command is queued after the earlier one's")
	assert.True(t, first.Contained)
	assert.False(t, second.Contained)
}

// A database that cannot answer produces an error, not a quiet no-op. An operator who is told a host was contained must not have to
// wonder whether it was, and the catch-up must report a sweep it could not complete rather than counting it as done.
func TestStoreFailuresAreReported(t *testing.T) {
	t.Parallel()
	contained := api.ContainmentState{HostID: "host-a", Version: 1, Epoch: 1}
	queueOK := func(context.Context, sqlx.ExecerContext, api.ContainmentState) (int64, error) { return 1, nil }

	t.Run("a closed database", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		require.NoError(t, f.db.Close())

		_, _, _, err := f.store.Set(t.Context(), "host-a", true, "why", "user:7", queueOK)
		require.Error(t, err)
		_, _, err = f.store.QueueCurrent(t.Context(), contained, queueOK)
		require.Error(t, err)
	})

	t.Run("a table that is not there", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		_, err := f.db.ExecContext(t.Context(), `DROP TABLE host_containment`)
		require.NoError(t, err)

		_, _, _, err = f.store.Set(t.Context(), "host-a", true, "why", "user:7", queueOK)
		require.Error(t, err, "the containment cannot be created")
		_, _, _, err = f.store.Set(t.Context(), "host-a", false, "why", "user:7", queueOK)
		require.Error(t, err, "the state cannot be read")
		_, _, err = f.store.QueueCurrent(t.Context(), contained, queueOK)
		require.Error(t, err, "the catch-up cannot read the state it meant to queue")
	})

	// Two hosts, and only the first cannot be queued: the second is what shows the sweep carried on. With one host the same
	// assertions would hold whether the sweep continued or stopped at the failure.
	t.Run("a sweep carries on past a host it cannot queue", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		for _, hostID := range []string{"host-a", "host-b"} {
			_, err := f.svc.Set(t.Context(), operator, "", hostID, true, "beaconing")
			require.NoError(t, err)
		}
		// Both commands expire, so the catch-up means to queue both states again.
		_, err := f.db.ExecContext(t.Context(), `UPDATE commands SET status = ?`, api.StatusExpired)
		require.NoError(t, err)

		enrollments := func(context.Context) ([]api.HostEnrollment, error) {
			return []api.HostEnrollment{
				{HostID: "host-a", EnrolledAt: f.enrolled["host-a"]},
				{HostID: "host-b", EnrolledAt: f.enrolled["host-b"]},
			}, nil
		}
		failFirst := func(ctx context.Context, q sqlx.ExecerContext, hostID, commandType string, payload []byte) (int64, error) {
			if hostID == "host-a" {
				return 0, errors.New("queue unavailable")
			}
			return f.commands.QueueTx(ctx, q, hostID, commandType, payload)
		}
		converger := containment.NewConverger(f.store, failFirst, f.notified.notify, enrollments, f.commands.LatestOfType, nil)

		queued, err := converger.Converge(t.Context())
		require.NoError(t, err, "one host that cannot be queued does not end the sweep")
		assert.Equal(t, 1, queued, "the second host was queued after the first failed")
		assert.Equal(t, []string{"host-a", "host-b", "host-b"}, f.notified.recorded(),
			"the two changes told the gateway, then the sweep told it about host-b alone")
	})

	t.Run("a command that cannot be queued by the catch-up", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		change, err := f.svc.Set(t.Context(), operator, "", "host-a", true, "beaconing")
		require.NoError(t, err)

		_, queued, err := f.store.QueueCurrent(t.Context(), change.State,
			func(context.Context, sqlx.ExecerContext, api.ContainmentState) (int64, error) {
				return 0, errors.New("queue unavailable")
			})
		require.Error(t, err)
		assert.False(t, queued)
	})
}

// The catch-up has its own transaction and its own notification, so the guarantee is checked there too: the command it queues is
// visible to another connection by the time the gateway is told to look for it.
func TestConverge_TheGatewayIsToldOnlyOnceTheCommandIsVisible(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	change, err := f.svc.Set(t.Context(), operator, "", "host-a", true, "beaconing")
	require.NoError(t, err)
	require.True(t, change.Changed)
	// The change's command expires, which is one of the states the catch-up queues again.
	_, err = f.db.ExecContext(t.Context(), `UPDATE commands SET status = ? WHERE id = ?`, api.StatusExpired, change.CommandID)
	require.NoError(t, err)

	queued, err := f.converger.Converge(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, queued)

	assert.Equal(t, []string{"host-a", "host-a"}, f.notified.recorded(), "the change and the catch-up each told the gateway")
	assert.Equal(t, []int{1, 2}, f.notified.commandsVisibleAtNotify(),
		"the catch-up's command is visible to another connection when the gateway is told about it")
}

// The catch-up reads every host's state at the start of a sweep and queues some time later. A host whose state changed in between has
// a command for the newer state already, and the sweep must not put the older one behind it.
// spec:server-host-containment/hosts-converge-on-their-containment-state/a-concurrent-change-is-not-overtaken-by-the-catch-up
func TestConverge_AStateThatChangedSinceTheSweepReadItQueuesNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	contained, _, _, err := f.store.Set(t.Context(), "host-a", true, "contain", "user:7",
		func(ctx context.Context, q sqlx.ExecerContext, state api.ContainmentState) (int64, error) {
			return f.commands.QueueTx(ctx, q, state.HostID, api.CommandTypeSetNetworkContainment, commandPayloadFor(state))
		})
	require.NoError(t, err)

	// The host moves on, as a concurrent change would between the sweep's read and its queue.
	_, _, _, err = f.store.Set(t.Context(), "host-a", false, "release", "user:7",
		func(ctx context.Context, q sqlx.ExecerContext, state api.ContainmentState) (int64, error) {
			return f.commands.QueueTx(ctx, q, state.HostID, api.CommandTypeSetNetworkContainment, commandPayloadFor(state))
		})
	require.NoError(t, err)

	before := len(f.containmentCommands(t, "host-a"))
	id, queued, err := f.store.QueueCurrent(t.Context(), contained,
		func(ctx context.Context, q sqlx.ExecerContext, state api.ContainmentState) (int64, error) {
			return f.commands.QueueTx(ctx, q, state.HostID, api.CommandTypeSetNetworkContainment, commandPayloadFor(state))
		})
	require.NoError(t, err)
	assert.False(t, queued, "the host no longer holds the state the sweep read")
	assert.Zero(t, id)
	assert.Len(t, f.containmentCommands(t, "host-a"), before, "no command was queued")
}

// A change whose command cannot be queued records nothing: the state and its command are written in one transaction, so the operator
// is told the change failed rather than left with a state whose command the catch-up has to notice (issue #1073).
// spec:server-host-containment/an-operator-contains-or-releases-a-host/a-change-whose-command-cannot-be-queued-records-nothing
func TestSet_ACommandThatCannotBeQueuedRecordsNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// The command is written through the transaction and the callback then fails, which is the case that proves the all-or-nothing
	// contract: a callback that failed before inserting would only show the state rolling back.
	failing := func(ctx context.Context, q sqlx.ExecerContext, hostID, commandType string, payload []byte) (int64, error) {
		if _, err := f.commands.QueueTx(ctx, q, hostID, commandType, payload); err != nil {
			return 0, err
		}
		return 0, errors.New("queue unavailable")
	}
	svc := containment.NewService(f.store, func(context.Context, string) (bool, error) { return true, nil }, failing,
		f.notified.notify, f.commands.LatestOfType, f.outbox, nil)

	_, err := svc.Set(t.Context(), operator, "", "host-a", true, "suspicious")
	require.Error(t, err)
	state, err := f.store.Get(t.Context(), "host-a")
	require.NoError(t, err)
	assert.False(t, state.Contained, "the state rolled back with the command")
	assert.Zero(t, state.Version)
	assert.Empty(t, f.auditRows(t, 0), "nothing happened, so nothing is audited")
	assert.Empty(t, f.notified.recorded(), "the gateway is told nothing")
	assert.Empty(t, f.containmentCommands(t, "host-a"), "the command written through the transaction rolled back with the state")
}

// Failures reading enrollment or commands fail the request rather than being treated as an answer.
func TestReadFailuresAreReturned(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	boom := errors.New("boom")
	_, err := containment.NewService(f.store, func(context.Context, string) (bool, error) { return false, boom }, f.commands.QueueTx,
		f.notified.notify,
		f.commands.LatestOfType, f.outbox, nil).Set(t.Context(), operator, "", "host-a", true, "x")
	require.ErrorIs(t, err, boom)

	_, err = f.svc.Set(t.Context(), operator, "", "host-a", true, "x")
	require.NoError(t, err)
	latestFails := func(context.Context, string, []string) (map[string]api.Command, error) { return nil, boom }
	_, err = containment.NewService(f.store, func(context.Context, string) (bool, error) { return true, nil }, f.commands.QueueTx,
		f.notified.notify,
		latestFails, f.outbox, nil).Get(t.Context(), "host-a")
	require.ErrorIs(t, err, boom)
	_, err = containment.NewConverger(f.store, f.commands.QueueTx, f.notified.notify,
		func(context.Context) ([]api.HostEnrollment, error) { return nil, boom },
		f.commands.LatestOfType, nil).Converge(t.Context())
	require.ErrorIs(t, err, boom)
	onlyHostA := func(context.Context) ([]api.HostEnrollment, error) {
		return []api.HostEnrollment{{HostID: "host-a"}}, nil
	}
	_, err = containment.NewConverger(f.store, f.commands.QueueTx, f.notified.notify, onlyHostA, latestFails, nil).Converge(t.Context())
	require.ErrorIs(t, err, boom)
}

// Loop runs the catch-up on its interval until its context ends.
func TestLoop_RunsTheCatchUpUntilCancelled(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	change, err := f.svc.Set(t.Context(), operator, "", "host-a", true, "suspicious")
	require.NoError(t, err)
	f.setStatus(t, change.CommandID, api.StatusExpired)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		f.converger.Loop(ctx, 10*time.Millisecond)
		close(done)
	}()
	require.Eventually(t, func() bool { return len(f.containmentCommands(t, "host-a")) == 2 }, 5*time.Second, 10*time.Millisecond)
	cancel()
	<-done
}

func TestConstructorsRequireTheirDependencies(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	enrolled := func(context.Context, string) (bool, error) { return true, nil }
	enrollments := func(context.Context) ([]api.HostEnrollment, error) { return nil, nil }
	assert.Panics(t, func() { containment.NewStore(nil) })
	assert.Panics(t, func() {
		containment.NewService(nil, enrolled, f.commands.QueueTx, f.notified.notify, f.commands.LatestOfType, f.outbox, nil)
	})
	assert.Panics(t, func() {
		containment.NewService(f.store, nil, f.commands.QueueTx, f.notified.notify, f.commands.LatestOfType, f.outbox, nil)
	})
	assert.Panics(t, func() {
		containment.NewService(f.store, enrolled, f.commands.QueueTx, f.notified.notify, f.commands.LatestOfType, nil, nil)
	}, "a service without an outbox could record a containment with nothing saying who made it")
	assert.Panics(t, func() {
		containment.NewConverger(f.store, nil, f.notified.notify, enrollments, f.commands.LatestOfType, nil)
	})
	assert.Panics(t, func() {
		containment.NewConverger(f.store, f.commands.QueueTx, f.notified.notify, nil, f.commands.LatestOfType, nil)
	})
}

// spec:server-host-containment/the-containment-state-is-readable/the-host-list-shows-every-host-with-a-state
func TestList_EveryHostWithAState(t *testing.T) {
	t.Parallel()
	t.Run("no host with a state", func(t *testing.T) {
		t.Parallel()
		got, err := newFixture(t).svc.List(t.Context())
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("contained and released hosts with their deliveries", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		contain, err := f.svc.Set(t.Context(), operator, "", "host-a", true, "suspicious")
		require.NoError(t, err)
		_, err = f.svc.Set(t.Context(), operator, "", "host-b", true, "suspicious")
		require.NoError(t, err)
		release, err := f.svc.Set(t.Context(), operator, "", "host-b", false, "cleared")
		require.NoError(t, err)

		got, err := f.svc.List(t.Context())
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, "host-a", got[0].HostID)
		assert.True(t, got[0].Contained)
		require.NotNil(t, got[0].Delivery)
		assert.Equal(t, api.ContainmentDelivery{CommandID: contain.CommandID, Status: api.StatusPending, Current: true}, *got[0].Delivery)
		assert.Equal(t, "host-b", got[1].HostID)
		assert.False(t, got[1].Contained, "a released host is listed with its release")
		require.NotNil(t, got[1].Delivery)
		assert.Equal(t, release.CommandID, got[1].Delivery.CommandID)
	})
	t.Run("a command history read failure", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		_, err := f.svc.Set(t.Context(), operator, "", "host-a", true, "suspicious")
		require.NoError(t, err)
		boom := errors.New("boom")
		latestFails := func(context.Context, string, []string) (map[string]api.Command, error) { return nil, boom }
		_, err = containment.NewService(f.store, func(context.Context, string) (bool, error) { return true, nil }, f.commands.QueueTx,
			f.notified.notify,
			latestFails, f.outbox, nil).List(t.Context())
		require.ErrorIs(t, err, boom)
	})
}

// pendingAudit decodes the audit entries the outbox holds, oldest first.
// auditRows returns the audit rows the changes so far produced, once the outbox has settled.
//
// A change no longer delivers its own row (issue #1089): it commits the entry and asks the sweep, which delivers it on its own
// goroutine. So reading the recorder straight after a change would be reading a race, and asserting the recorder is EMPTY straight
// after one would be asserting nothing at all.
//
// The sweep this starts runs at the production interval, minutes away, so nothing here arrives on a tick. A row arrives because the
// change asked for it, and a service that stopped asking fails these tests rather than passing minutes later. Settled means the
// outbox is empty as well as the rows delivered, so a test expecting one row fails on a second rather than racing it.
func (f *fixture) auditRows(t *testing.T, want int) []identityapi.AuditEvent {
	t.Helper()
	f.sweeping.Do(func() { go f.drain.SweepLoop(t.Context(), 0) })
	require.Eventually(t, func() bool {
		pending, err := f.outbox.PendingAuditEntries(t.Context(), 1)
		return err == nil && len(pending) == 0 && len(f.audit.recorded()) >= want
	}, 10*time.Second, 5*time.Millisecond, "the audit rows the changes committed are delivered without the change waiting for them")
	rows := f.audit.recorded()
	require.Len(t, rows, want)
	return rows
}

func (f *fixture) pendingAudit(t *testing.T) []identityapi.AuditEvent {
	t.Helper()
	pending, err := f.outbox.PendingAuditEntries(t.Context(), auditoutbox.DrainBatch)
	require.NoError(t, err)
	out := make([]identityapi.AuditEvent, 0, len(pending))
	for _, p := range pending {
		e, err := auditoutbox.Decode(p.Payload)
		require.NoError(t, err)
		out = append(out, e)
	}
	return out
}

// spec:server-host-containment/a-containment-change-commits-its-audit-entry/a-delivery-failure-delays-the-audit-row
//
// The audit row is what says who cut a host off the network and why, and before issue #1070 it was written after the change had
// committed and only logged when it failed. Here the store is down for the change and back by the time the entry is delivered, and
// the row still arrives whole: the actor, the address they acted from, the reason, and the command the change queued.
func TestSet_ARecorderFailureDelaysTheAuditRowRatherThanLosingIt(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.audit.goesDown(errors.New("audit store unavailable"))

	// A real change runs under the request's span, and the row has to name that trace however long the delivery takes.
	spanTrace, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	require.NoError(t, err)
	spanID, err := trace.SpanIDFromHex("00f067aa0ba902b7")
	require.NoError(t, err)
	ctx := trace.ContextWithSpanContext(t.Context(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: spanTrace, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	}))
	traceID := identityapi.TraceIDFromContext(ctx)
	require.NotEmpty(t, traceID, "the fixture must run under a real span or the assertion below proves nothing")

	change, err := f.svc.Set(ctx, operator, "203.0.113.5", "host-a", true, "beaconing to a known C2")
	require.NoError(t, err, "a change is not refused because its audit row could not be written")
	assert.True(t, change.Changed)
	assert.Empty(t, f.audit.recorded(), "the store is down, so no row yet")

	held := f.pendingAudit(t)
	require.Len(t, held, 1, "the entry committed with the change")
	assert.Equal(t, identityapi.AuditHostContain, held[0].Action)

	f.audit.comesBack()
	delivered, err := f.drain.Drain(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, delivered)

	events := f.audit.recorded()
	require.Len(t, events, 1)
	assert.Equal(t, identityapi.AuditHostContain, events[0].Action)
	assert.Equal(t, operator, events[0].Actor)
	assert.Equal(t, "host-a", events[0].TargetID)
	assert.Equal(t, "203.0.113.5", events[0].RemoteAddr, "the address the operator acted from survives the outbox")
	assert.Equal(t, "beaconing to a known C2", events[0].Payload["reason"])
	assert.EqualValues(t, change.CommandID, events[0].Payload["command_id"])
	assert.Equal(t, traceID, events[0].TraceID,
		"the entry carries the trace of the request that made the change; the drain detaches its own so it cannot supply one")
	assert.Empty(t, f.pendingAudit(t), "a delivered entry is cleared")
}

// spec:server-host-containment/a-containment-change-commits-its-audit-entry/a-refused-change-leaves-no-audit-entry
//
// The entry commits with the change, so a change that records nothing leaves nothing to deliver. Without this the outbox would turn a
// refused containment into an audit row claiming a host was contained.
//
// The entry's own write is what fails here, through a service whose outbox names a table that does not exist, and the state and the
// command are then asserted to have rolled back with it. That is the direction that proves the production enqueue runs inside the
// change's transaction: a failing command queue would leave the outbox empty however the entry was written, and would pass even if
// the service enqueued on its own connection.
func TestSet_ARefusedChangeLeavesNoAuditEntry(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	enrolled := func(context.Context, string) (bool, error) { return true, nil }
	svc := containment.NewService(f.store, enrolled, f.commands.QueueTx, f.notified.notify, f.commands.LatestOfType,
		auditoutbox.NewStore(f.db, "absent_audit_outbox"), f.drain)

	_, err := svc.Set(t.Context(), operator, "203.0.113.5", "host-a", true, "suspicious")
	require.Error(t, err, "a change whose audit entry cannot be written is refused, not recorded without one")

	state, err := f.store.Get(t.Context(), "host-a")
	require.NoError(t, err)
	assert.Zero(t, state.Version, "the state rolled back with the entry")
	assert.False(t, state.Contained)
	assert.Empty(t, f.containmentCommands(t, "host-a"), "the command rolled back with the entry")
	assert.Empty(t, f.pendingAudit(t))
	assert.Empty(t, f.auditRows(t, 0))

	// A request for the state a host already has changes nothing, so it records nothing either.
	_, err = f.svc.Set(t.Context(), operator, "203.0.113.5", "host-a", false, "already released")
	require.NoError(t, err)
	assert.Empty(t, f.pendingAudit(t))
	assert.Empty(t, f.auditRows(t, 0))
}
