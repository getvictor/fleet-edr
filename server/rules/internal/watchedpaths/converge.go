package watchedpaths

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"time"

	"github.com/fleetdm/edr/server/catchup"
	"github.com/fleetdm/edr/server/rules/api"
)

// DefaultConvergeInterval is how often the catch-up runs. A host that enrolls, reinstalls, or comes back after its command aged out
// gets the set within this long of its next poll. The policy, including how long a failed command counts as delivered, is shared with
// the containment catch-up (issue #1071).
const DefaultConvergeInterval = catchup.DefaultInterval

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
	catchup.Loop(ctx, "watchedpaths", c.Converge, interval, c.logger)
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

// needsSet reports whether a host should be sent the current set, given its latest set_watched_paths command. The decision is
// catchup's; what belongs here is what this context's command means, which is whether its payload carries the current set. The zero
// WatchedPathCommand is a host that has never been sent one, and carries nothing.
func needsSet(cmd api.WatchedPathCommand, e api.WatchedPathEnrollment, set api.WatchedPathSet, now time.Time) bool {
	// This context records a terminal time as a zero value where the shared decision takes a nil, so an unfinished command reads as
	// unfinished rather than as one that completed at the zero time.
	var completedAt *time.Time
	if !cmd.CompletedAt.IsZero() {
		completedAt = &cmd.CompletedAt
	}
	return catchup.Needed(catchup.Latest{
		Queued:      cmd.Payload != nil,
		Carries:     carriesSet(cmd, set),
		CreatedAt:   cmd.CreatedAt,
		Status:      catchup.Status(cmd.Status),
		CompletedAt: completedAt,
	}, e.EnrolledAt, now)
}

// carriesSet reports whether a command's payload delivers the current set. The same version with a different epoch is a different
// set, as after a database restore that sent versions backwards.
func carriesSet(cmd api.WatchedPathCommand, set api.WatchedPathSet) bool {
	var queued api.SetWatchedPathsPayload
	return json.Unmarshal(cmd.Payload, &queued) == nil &&
		queued.Version == set.Version && queued.Epoch == set.UpdatedAt.UnixMicro()
}
