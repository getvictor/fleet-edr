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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
	"github.com/fleetdm/edr/server/response/internal/containment"
	"github.com/fleetdm/edr/server/response/internal/mysql"
	"github.com/fleetdm/edr/server/response/internal/service"
	"github.com/fleetdm/edr/server/response/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// recordingAudit keeps every audit event recorded.
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

// fixture is a containment service and converger over an isolated database, with the real command store behind them.
type fixture struct {
	store     *containment.Store
	svc       *containment.Service
	converger *containment.Converger
	commands  *service.Service
	audit     *recordingAudit
	// enrolled is each enrolled host's enrollment time.
	enrolled map[string]time.Time
}

var operator = identityapi.PrincipalRef{ID: "user:7", Type: "user", Label: "ir@example.com"}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	f := &fixture{
		store: containment.NewStore(db), commands: service.New(mysql.NewStore(db), nil, nil), audit: &recordingAudit{},
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
	f.svc = containment.NewService(f.store, isEnrolled, f.commands.Insert, f.commands.LatestOfType, f.audit, nil)
	f.converger = containment.NewConverger(f.store, f.commands.Insert, enrollments, f.commands.LatestOfType, nil)
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

func payloadOf(t *testing.T, cmd api.Command) api.SetNetworkContainmentPayload {
	t.Helper()
	var p api.SetNetworkContainmentPayload
	require.NoError(t, json.Unmarshal(cmd.Payload, &p))
	return p
}

// spec:server-host-containment/an-operator-contains-or-releases-a-host/an-operator-contains-a-host
// spec:server-host-containment/an-operator-contains-or-releases-a-host/a-release-is-recorded-the-same-way
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

	events := f.audit.recorded()
	require.Len(t, events, 2)
	assert.Equal(t, identityapi.AuditHostContain, events[0].Action)
	assert.Equal(t, identityapi.AuditHostRelease, events[1].Action)
	for i, e := range events {
		assert.Equal(t, operator, e.Actor)
		assert.Equal(t, "host", e.TargetType)
		assert.Equal(t, "host-a", e.TargetID)
		assert.Equal(t, "203.0.113.5", e.RemoteAddr)
		assert.Equal(t, int64(i+1), e.Payload["version"])
	}
	assert.Equal(t, contain.State.Epoch, events[0].Payload["epoch"])
	assert.Equal(t, release.State.Epoch, events[1].Payload["epoch"])
	assert.Equal(t, "beaconing to a known C2", events[0].Payload["reason"])
	assert.Equal(t, contain.CommandID, events[0].Payload["command_id"])
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
			assert.Empty(t, f.audit.recorded())
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
	assert.Len(t, f.audit.recorded(), 1)
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
		_, err := containment.NewConverger(f.store, f.commands.Insert, enrollments, latest, nil).Converge(t.Context())
		require.NoError(t, err)
		assert.Equal(t, [][]string{{"host-a"}}, asked)
	})
}

// A change whose command could not be queued is still recorded and audited: the state is authoritative and the catch-up queues it.
func TestSet_ACommandThatCannotBeQueuedDoesNotFailTheChange(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	failing := func(context.Context, string, string, []byte) (int64, error) {
		return 0, errors.New("queue unavailable")
	}
	svc := containment.NewService(f.store, func(context.Context, string) (bool, error) { return true, nil }, failing,
		f.commands.LatestOfType, f.audit, nil)

	change, err := svc.Set(t.Context(), operator, "", "host-a", true, "suspicious")
	require.NoError(t, err)
	assert.True(t, change.Changed)
	assert.Zero(t, change.CommandID)
	state, err := f.store.Get(t.Context(), "host-a")
	require.NoError(t, err)
	assert.True(t, state.Contained)
	events := f.audit.recorded()
	require.Len(t, events, 1)
	assert.NotContains(t, events[0].Payload, "command_id")

	queued, err := f.converger.Converge(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, queued, "the catch-up queues the state the change could not")
}

// Failures reading enrollment or commands fail the request rather than being treated as an answer.
func TestReadFailuresAreReturned(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	boom := errors.New("boom")
	_, err := containment.NewService(f.store, func(context.Context, string) (bool, error) { return false, boom }, f.commands.Insert,
		f.commands.LatestOfType, nil, nil).Set(t.Context(), operator, "", "host-a", true, "x")
	require.ErrorIs(t, err, boom)

	_, err = f.svc.Set(t.Context(), operator, "", "host-a", true, "x")
	require.NoError(t, err)
	latestFails := func(context.Context, string, []string) (map[string]api.Command, error) { return nil, boom }
	_, err = containment.NewService(f.store, func(context.Context, string) (bool, error) { return true, nil }, f.commands.Insert,
		latestFails, nil, nil).Get(t.Context(), "host-a")
	require.ErrorIs(t, err, boom)
	_, err = containment.NewConverger(f.store, f.commands.Insert, func(context.Context) ([]api.HostEnrollment, error) { return nil, boom },
		f.commands.LatestOfType, nil).Converge(t.Context())
	require.ErrorIs(t, err, boom)
	onlyHostA := func(context.Context) ([]api.HostEnrollment, error) {
		return []api.HostEnrollment{{HostID: "host-a"}}, nil
	}
	_, err = containment.NewConverger(f.store, f.commands.Insert, onlyHostA, latestFails, nil).Converge(t.Context())
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
	assert.Panics(t, func() { containment.NewService(nil, enrolled, f.commands.Insert, f.commands.LatestOfType, nil, nil) })
	assert.Panics(t, func() { containment.NewService(f.store, nil, f.commands.Insert, f.commands.LatestOfType, nil, nil) })
	assert.Panics(t, func() { containment.NewConverger(f.store, nil, enrollments, f.commands.LatestOfType, nil) })
	assert.Panics(t, func() { containment.NewConverger(f.store, f.commands.Insert, nil, f.commands.LatestOfType, nil) })
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
		_, err = containment.NewService(f.store, func(context.Context, string) (bool, error) { return true, nil }, f.commands.Insert,
			latestFails, nil, nil).List(t.Context())
		require.ErrorIs(t, err, boom)
	})
}
