package containment

import (
	"github.com/jmoiron/sqlx"

	"context"
	"log/slog"
	"time"

	"github.com/fleetdm/edr/server/catchup"
	"github.com/fleetdm/edr/server/response/api"
)

// DefaultConvergeInterval is how often the catch-up runs. A host whose command expired, that re-enrolled, or whose command could not be
// queued gets its state within this long of its next poll. The policy, including how long a failed command counts as delivered, is
// shared with the watched-path catch-up (issue #1071).
const DefaultConvergeInterval = catchup.DefaultInterval

// Converger queues each host's containment state again when its latest command does not deliver it. It mirrors the watched-path
// catch-up (#998) per host: a queued command lives an hour, a reinstall loses the extension's persisted state, and a change whose
// command could not be queued has none.
type Converger struct {
	store       *Store
	queue       CommandQueuer
	notify      Notifier
	enrollments api.ActiveEnrollmentLister
	latest      LatestCommands
	logger      *slog.Logger
	now         func() time.Time
}

// NewConverger builds a Converger. Every dependency but logger is required.
func NewConverger(store *Store, queue CommandQueuer, notify Notifier, enrollments api.ActiveEnrollmentLister,
	latest LatestCommands, logger *slog.Logger) *Converger {
	if store == nil || queue == nil || notify == nil || enrollments == nil || latest == nil {
		panic("containment.NewConverger: store, queue, notify, enrollments and latest are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Converger{store: store, queue: queue, notify: notify, enrollments: enrollments, latest: latest, logger: logger,
		now: time.Now}
}

// queueCurrent queues one host's state through the store's locked re-read, logging a failure rather than ending the sweep: the other
// hosts' states are still worth queuing, and this one is tried again on the next sweep.
func (c *Converger) queueCurrent(ctx context.Context, state api.ContainmentState) (int64, bool) {
	commandID, queued, err := c.store.QueueCurrent(ctx, state,
		func(ctx context.Context, q sqlx.ExecerContext, current api.ContainmentState) (int64, error) {
			return c.queue(ctx, q, current.HostID, api.CommandTypeSetNetworkContainment, commandPayload(current))
		})
	if err != nil {
		c.logger.WarnContext(ctx, "containment: catch-up could not queue a host's state", "host_id", state.HostID, "err", err)
		return 0, false
	}
	return commandID, queued
}

// Loop runs Converge every interval until ctx is cancelled; a zero or negative interval means DefaultConvergeInterval.
//
// Not leader-gated, like the watched-path catch-up: replicas that sweep at the same moment can each queue a host's state, and the
// extension turns the second copy away because it is not newer, so a race costs a duplicate command row rather than a wrong result.
func (c *Converger) Loop(ctx context.Context, interval time.Duration) {
	catchup.Loop(ctx, "containment", c.Converge, interval, c.logger)
}

// Converge queues the state of every actively enrolled host with one whose latest command does not deliver it, and returns how many
// commands it queued.
func (c *Converger) Converge(ctx context.Context) (int, error) {
	states, err := c.store.All(ctx)
	if err != nil || len(states) == 0 {
		return 0, err
	}
	enrolled, err := c.enrollments(ctx)
	if err != nil {
		return 0, err
	}
	enrolledAt := make(map[string]time.Time, len(enrolled))
	for _, e := range enrolled {
		enrolledAt[e.HostID] = e.EnrolledAt
	}
	// Only enrolled hosts can be queued, and rows are kept for every host ever contained, so the command-history read is limited to them.
	hostIDs := make([]string, 0, len(states))
	for _, state := range states {
		if _, ok := enrolledAt[state.HostID]; ok {
			hostIDs = append(hostIDs, state.HostID)
		}
	}
	if len(hostIDs) == 0 {
		return 0, nil
	}
	latest, err := c.latest(ctx, api.CommandTypeSetNetworkContainment, hostIDs)
	if err != nil {
		return 0, err
	}
	now, queued := c.now(), 0
	for _, state := range states {
		at, ok := enrolledAt[state.HostID]
		if !ok || !needsState(latest[state.HostID], state, at, now) {
			continue
		}
		// Under the host's lock, against the state the host holds now: this sweep read its states some time ago, and a change that
		// committed since has queued a command of its own, which this one must not be put behind (issue #1073).
		_, ok = c.queueCurrent(ctx, state)
		if !ok {
			continue
		}
		c.notify(state.HostID)
		queued++
	}
	if queued > 0 {
		c.logger.InfoContext(ctx, "containment: queued the state for hosts whose command did not deliver it", "queued", queued)
	}
	return queued, nil
}

// needsState reports whether a host should be sent its state, given its latest set_network_containment command. The decision is
// catchup's; what belongs here is what this context's command means, which is whether its payload carries the host's current state.
// The zero Command is a host that has never been sent one, and carries nothing.
func needsState(cmd api.Command, state api.ContainmentState, enrolledAt, now time.Time) bool {
	return catchup.Needed(catchup.Latest{
		Queued:      cmd.ID != 0,
		Carries:     carries(cmd, state),
		CreatedAt:   cmd.CreatedAt,
		Status:      cmd.Status.Catchup(),
		CompletedAt: cmd.CompletedAt,
	}, enrolledAt, now)
}
