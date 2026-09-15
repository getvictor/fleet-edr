package containment

import (
	"context"
	"log/slog"
	"time"

	"github.com/fleetdm/edr/server/response/api"
)

// DefaultConvergeInterval is how often the catch-up runs. A host whose command expired, that re-enrolled, or whose command could not be
// queued gets its state within this long of its next poll.
const DefaultConvergeInterval = 5 * time.Minute

// failedRetryAfter is how long a failed command counts as delivered before the state is queued again. A failure is usually an agent or
// a host that cannot contain (an older agent, or no network extension), which fails it the same way every time, so retrying each sweep
// would fill that host's command history; retrying rarely still reaches one that has since been upgraded.
const failedRetryAfter = 6 * time.Hour

// Converger queues each host's containment state again when its latest command does not deliver it. It mirrors the watched-path
// catch-up (#998) per host: a queued command lives an hour, a reinstall loses the extension's persisted state, and a change whose
// command could not be queued has none.
type Converger struct {
	store       *Store
	insert      CommandInserter
	enrollments api.ActiveEnrollmentLister
	latest      LatestCommands
	logger      *slog.Logger
	now         func() time.Time
}

// NewConverger builds a Converger. Every dependency but logger is required.
func NewConverger(store *Store, insert CommandInserter, enrollments api.ActiveEnrollmentLister, latest LatestCommands,
	logger *slog.Logger) *Converger {
	if store == nil || insert == nil || enrollments == nil || latest == nil {
		panic("containment.NewConverger: store, insert, enrollments and latest are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Converger{store: store, insert: insert, enrollments: enrollments, latest: latest, logger: logger, now: time.Now}
}

// Loop runs Converge every interval until ctx is cancelled; a zero or negative interval means DefaultConvergeInterval.
//
// Not leader-gated, like the watched-path catch-up: replicas that sweep at the same moment can each queue a host's state, and the
// extension turns the second copy away because it is not newer, so a race costs a duplicate command row rather than a wrong result.
func (c *Converger) Loop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultConvergeInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := c.Converge(ctx); err != nil {
				c.logger.WarnContext(ctx, "containment: catch-up failed; retrying next interval", "err", err)
			}
		}
	}
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
		if _, err := c.insert(ctx, state.HostID, api.CommandTypeSetNetworkContainment, commandPayload(state)); err != nil {
			c.logger.WarnContext(ctx, "containment: catch-up could not queue a host's state", "host_id", state.HostID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.logger.InfoContext(ctx, "containment: queued the state for hosts whose command did not deliver it", "queued", queued)
	}
	return queued, nil
}

// needsState reports whether a host should be sent its state, given its latest set_network_containment command. The zero Command is a
// host that has never been sent one.
func needsState(cmd api.Command, state api.ContainmentState, enrolledAt, now time.Time) bool {
	// The zero Command, a host never sent one, carries no state.
	if !carries(cmd, state) {
		return true
	}
	// Queued before, or at, the host's latest enrollment: a reinstall in between removed the extension's copy. Both times are on the
	// database clock; a tie counts as before, since a duplicate copy is harmless and a missing one is not.
	if !cmd.CreatedAt.After(enrolledAt) {
		return true
	}
	switch cmd.Status {
	case api.StatusExpired, api.StatusCancelled:
		return true
	case api.StatusFailed:
		// Every failure is stamped with its completion time; one without it is not retried early.
		return cmd.CompletedAt != nil && now.Sub(*cmd.CompletedAt) >= failedRetryAfter
	case api.StatusPending, api.StatusAcked, api.StatusCompleted:
		// On its way or delivered. An offline host keeps its command pending until it reconnects or the command ages out, so it is not
		// sent a new copy every interval.
		return false
	}
	return false
}
