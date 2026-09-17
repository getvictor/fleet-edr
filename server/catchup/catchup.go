// Package catchup decides when a host should be sent a state it may not have, and runs the sweep that asks.
//
// Two contexts push a desired state to hosts as a command and then have to notice the hosts that did not get it: the watched-path set
// (issue #998) and host containment (issue #1068). A push reaches the hosts enrolled at the time, but a queued command lives an hour,
// a host enrolled later has none, and a reinstall loses the extension's copy. Both closed those the same way and each kept its own
// copy of the policy, so a change to delivery or retry semantics made in one could silently miss the other (issue #1071).
//
// What is shared is the decision and the loop. What is not is where a state comes from, what its command payload says, and how a
// caller queues one: those differ per context and stay there. A context maps its own command onto Latest and asks Needed.
package catchup

import (
	"context"
	"log/slog"
	"time"
)

// DefaultInterval is how often a sweep runs. A host that enrolls, reinstalls, or comes back after its command aged out gets the state
// within this long of its next poll.
const DefaultInterval = 5 * time.Minute

// FailedRetryAfter is how long a failed command counts as delivered before the state is queued again.
//
// A failure is usually an agent that predates the command and fails it the same way every time, so retrying every sweep would fill
// that host's command history with the same failure. Retrying rarely still reaches a host whose agent has since been upgraded, or
// whose extension was briefly unreachable.
const FailedRetryAfter = 6 * time.Hour

// Status is the part of a command's lifecycle this decision reads. Each context maps its own vocabulary onto it, so the policy below
// is written once rather than against two spellings of the same five states.
type Status string

const (
	// StatusPending, StatusAcked and StatusCompleted all mean the command is on its way or has arrived.
	StatusPending   Status = "pending"
	StatusAcked     Status = "acked"
	StatusCompleted Status = "completed"
	// StatusFailed is a command the host refused or could not apply. Retried once FailedRetryAfter has passed.
	StatusFailed Status = "failed"
	// StatusExpired and StatusCancelled are commands that stopped being live without the host acting on them.
	StatusExpired   Status = "expired"
	StatusCancelled Status = "cancelled"
)

// Latest is a host's most recent command of the type carrying the state, as the decision needs to see it.
type Latest struct {
	// Queued is false for a host that has never been sent one. Its other fields are then meaningless.
	Queued bool
	// Carries reports whether this command delivers the state the host should have now. The context decides it, because only the
	// context knows what its payload means: a watched-path set compares the set's version and epoch, containment the host's.
	Carries bool
	// CreatedAt is when the command was queued, on the database clock.
	CreatedAt time.Time
	Status    Status
	// CompletedAt is when the command stopped being live, on the database clock. Nil for one that has not.
	CompletedAt *time.Time
}

// Needed reports whether the host should be sent the state again.
//
// enrolledAt is the host's latest enrollment and now this replica's clock. Both command times are the database's, so replica skew
// cannot reorder a command against an enrollment; skew of seconds is immaterial against the six-hour failure window.
func Needed(cmd Latest, enrolledAt, now time.Time) bool {
	// Never sent one. Nothing exists to conflict with, whatever version wrote what.
	if !cmd.Queued {
		return true
	}
	// An unrecognized status is left alone, and this is checked BEFORE anything else about the command. A status this package does
	// not know was written by a newer version, which also knows things this one does not: its payload may be a shape this version
	// reads as carrying the wrong state, and it may have been queued against an enrollment this version cannot see. Asking those
	// questions first and resending on the answer is how an older replica ends up fighting the newer one that wrote the command,
	// which is the outcome leaving it alone exists to avoid.
	if !recognized(cmd.Status) {
		return false
	}
	// Sent one carrying a state that is no longer the host's.
	if !cmd.Carries {
		return true
	}
	// Queued before, or at, the host's latest enrollment: a reinstall in between removed the extension's copy. A tie counts as
	// before, since a duplicate copy is harmless and a missing one is not.
	if !cmd.CreatedAt.After(enrolledAt) {
		return true
	}
	switch cmd.Status {
	case StatusExpired, StatusCancelled:
		// Stopped being live without the host acting on it, so nothing delivered the state.
		return true
	case StatusFailed:
		// A failure with no completion time is not retried early; nothing says how long ago it failed.
		return cmd.CompletedAt != nil && now.Sub(*cmd.CompletedAt) >= FailedRetryAfter
	case StatusPending, StatusAcked, StatusCompleted:
		// On its way or delivered. An offline host keeps its command pending until it reconnects, when the control stream delivers it
		// or the poll ages it out and the next sweep queues a fresh copy, so an offline host is not sent a new copy every interval.
		return false
	}
	// Unreachable: recognized() above admits exactly the six cases the switch covers, and this is here because the compiler cannot
	// see that. A status that reached here would be one recognized() admits and the switch forgot, so it is left alone, as an
	// unrecognized one is.
	return false
}

// recognized reports whether this version knows what a status means. Every caller maps its own vocabulary onto these, so a status
// that is not one of them came from a version that has more of them.
func recognized(s Status) bool {
	switch s {
	case StatusPending, StatusAcked, StatusCompleted, StatusFailed, StatusExpired, StatusCancelled:
		return true
	}
	return false
}

// Sweep is one pass of a context's catch-up, reporting how many hosts it queued the state for.
type Sweep func(ctx context.Context) (int, error)

// Loop runs sweep every interval until ctx is cancelled; a zero or negative interval means DefaultInterval. subject names the caller
// in the failure log ("watchedpaths", "containment").
//
// Not leader-gated, and it does not need to be. Two replicas sweeping at the same moment can each queue the state for one host, and
// the extension turns the second copy away because it is not newer than the first, so a race costs a duplicate command row rather
// than a wrong result. A leader lock would hold a pooled connection for the life of the process to prevent that (issue #722).
func Loop(ctx context.Context, subject string, sweep Sweep, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := sweep(ctx); err != nil {
				logger.WarnContext(ctx, "catch-up failed; retrying next interval", "subject", subject, "err", err)
			}
		}
	}
}
