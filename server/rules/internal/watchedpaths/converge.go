package watchedpaths

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"time"

	"github.com/fleetdm/edr/server/rules/api"
)

// DefaultConvergeInterval is how often the catch-up runs. A host that enrolls, reinstalls, or comes back after its command aged out
// gets the set within this long of its next poll.
const DefaultConvergeInterval = 5 * time.Minute

// failedRetryAfter is how long a failed command counts as delivered before the set is queued again. A failure is usually an agent
// that predates the command, which fails it the same way every time, so retrying each sweep would fill that host's command history;
// retrying rarely still reaches a host whose agent has since been upgraded, or whose extension was briefly unreachable.
const failedRetryAfter = 6 * time.Hour

// Converger queues the current set for hosts that do not have it (issue #998). The push on a change reaches the hosts enrolled then,
// but a queued command lives an hour, a host enrolled later has none, and a reinstall loses the extension's persisted set; this closes
// all three without the host asking.
type Converger struct {
	store       *Store
	commands    func(ctx context.Context, hostIDs []string, commandType string, payload []byte) (int, error)
	enrollments api.WatchedPathEnrollmentLister
	latest      api.WatchedPathCommandLister
	logger      *slog.Logger
	now         func() time.Time
}

// NewConverger builds a Converger. Every dependency is required.
func NewConverger(store *Store, commands func(ctx context.Context, hostIDs []string, commandType string, payload []byte) (int, error),
	enrollments api.WatchedPathEnrollmentLister, latest api.WatchedPathCommandLister, logger *slog.Logger) *Converger {
	if store == nil || commands == nil || enrollments == nil || latest == nil {
		panic("watchedpaths.NewConverger: store, commands, enrollments and latest are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Converger{store: store, commands: commands, enrollments: enrollments, latest: latest, logger: logger, now: time.Now}
}

// Loop runs Converge every interval until ctx is cancelled; a zero or negative interval means DefaultConvergeInterval.
//
// Not leader-gated. Replicas that sweep at the same moment can each queue the set for the same host, and the extension turns the
// second copy away because it is not newer than the first, so a race costs a duplicate command row rather than a wrong result; a
// leader lock would hold a pooled connection for the life of the process to prevent that (issue #722).
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
				c.logger.WarnContext(ctx, "watchedpaths: catch-up failed; retrying next interval", "err", err)
			}
		}
	}
}

// Converge queues the current set for every enrolled host that needs it and returns how many hosts it queued it for. Nothing is queued
// while the set has never been changed, since every host already watches the empty set.
func (c *Converger) Converge(ctx context.Context) (int, error) {
	set, err := c.store.Get(ctx)
	if err != nil || set.Version == 0 {
		return 0, err
	}
	enrolled, err := c.enrollments(ctx)
	if err != nil {
		return 0, err
	}
	hostIDs := make([]string, len(enrolled))
	for i, e := range enrolled {
		hostIDs[i] = e.HostID
	}
	latest, err := c.latest(ctx, api.CommandTypeSetWatchedPaths, hostIDs)
	if err != nil {
		return 0, err
	}
	now := c.now()
	var stale []string
	for _, e := range enrolled {
		if needsSet(latest[e.HostID], e, set, now) {
			stale = append(stale, e.HostID)
		}
	}
	if len(stale) == 0 {
		return 0, nil
	}
	slices.Sort(stale)
	inserted, err := c.commands(ctx, stale, api.CommandTypeSetWatchedPaths, commandPayload(set))
	c.logger.InfoContext(ctx, "watchedpaths: queued the set for hosts that did not have it",
		"version", set.Version, "hosts", len(stale), "queued", inserted)
	return inserted, err
}

// needsSet reports whether a host should be sent the current set, given its latest set_watched_paths command. The zero WatchedPathCommand
// is a host that has never been sent one.
func needsSet(cmd api.WatchedPathCommand, e api.WatchedPathEnrollment, set api.WatchedPathSet, now time.Time) bool {
	if cmd.Payload == nil {
		return true
	}
	// The same version with a different epoch is a different set, as after a database restore that sent versions backwards.
	var queued api.SetWatchedPathsPayload
	if json.Unmarshal(cmd.Payload, &queued) != nil || queued.Version != set.Version || queued.Epoch != set.UpdatedAt.UnixMicro() {
		return true
	}
	// Queued before, or at, the host's latest enrollment: a reinstall in between removed the extension's copy. Both times are on the
	// database clock (commands.created_at and enrollments.enrolled_at), so skew between replicas and the database cannot reorder them;
	// a tie counts as before, since a duplicate copy is harmless and a missing one is not.
	if !cmd.CreatedAt.After(e.EnrolledAt) {
		return true
	}
	switch cmd.Status {
	case "expired", "cancelled":
		return true
	case "failed":
		// now is this replica's clock and completed_at the database's; skew of seconds is immaterial against a six-hour window.
		return now.Sub(cmd.CompletedAt) >= failedRetryAfter
	default:
		// Pending, acked or completed: on its way or delivered. A host that is offline keeps its command pending until it reconnects,
		// when the control stream delivers it or the poll ages it out (and the next sweep queues a fresh copy), so an offline host is
		// not sent a new copy every interval.
		return false
	}
}
