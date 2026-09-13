package mysql

import (
	"context"
	"fmt"
	"strings"

	"github.com/fleetdm/edr/server/endpoint/api"
)

// Store is the recorder the detection engine depends on. Asserted here so a signature drift on either side is a compile error in
// this package rather than a wiring failure at boot.
var _ api.HealthEpisodeRecorder = (*Store)(nil)

// OpenHealthEpisode opens an episode for a component fault, and reports whether this call is what opened it.
//
// Idempotence is the schema's job, not this function's: `host_health_episodes` is unique on (host_id, source_event_id), so a second
// attempt to record the same occurrence collides. Doing it that way rather than with a read-then-write matters because the write
// path is concurrent across replicas, and a SELECT-then-INSERT would let two workers handling one redelivered event both observe
// "nothing recorded" and both insert.
//
// Keyed on the OCCURRENCE rather than on "is an episode open for this component" because that is the repetition the server actually
// sees. The agent emits one event per outage (its self-heal re-asserts health level state on every later report but fires the event
// only at the edge where its repair budget is spent), and event delivery is at-least-once, so the repeat is a redelivery of that
// one event. An open-episode key would stop matching the moment the episode closed and let a late redelivery record the same outage
// twice.
//
// The collision is absorbed with a no-op ON DUPLICATE KEY UPDATE rather than with INSERT IGNORE. IGNORE downgrades every error in
// the statement to a warning, not just the collision this wants, so an overlong value would be silently truncated into its column
// and reported as a successfully recorded episode.
//
// The returned flag is what a caller logs on: a redelivery is routine and must stay silent.
func (s *Store) OpenHealthEpisode(ctx context.Context, e api.HealthEpisode) (int64, bool, error) {
	// LAST_INSERT_ID(id) on the duplicate path is what makes the existing row's id come back from a statement that inserted nothing.
	// Without it a redelivery would report id 0, and a caller keying follow-on work on the episode could not redo that work.
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO host_health_episodes
			(host_id, component, subject, kind, source_event_id, severity, title, description, detail, opened_at_ns)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)
	`, e.HostID, e.Component, e.Subject, e.Kind, e.SourceEventID, e.Severity, e.Title, e.Description, e.Detail, e.OpenedAtNs)
	if err != nil {
		return 0, false, fmt.Errorf("open host health episode: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, false, fmt.Errorf("open host health episode id: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, false, fmt.Errorf("open host health episode rows affected: %w", err)
	}
	// 1 for a fresh insert, 0 for the no-op update that absorbed a redelivery. MySQL reports 2 only when the update CHANGES a row,
	// and LAST_INSERT_ID(id) sets the value to itself, so it never does.
	return id, n == 1, nil
}

// CloseHealthEpisodes closes hostID's open episodes for the components in recovered, stamping each with the instant that component
// was observed healthy, and returns how many it closed.
//
// Driven by the status check-in because that is the only moment the server learns a component recovered, and the check-in already
// carries the full component list.
//
// recovered names the components the snapshot reports HEALTHY, and the match is positive on purpose. Closing on the complement
// (every component not currently reporting a fault) would also close the episode of a component that has vanished from the snapshot
// entirely, and that is a resolution nobody observed: an agent that stops reporting a component has not told us the fault ended, so
// stamping an end time would be inventing the one number the record exists to provide. An episode for a component that stops being
// reported stays open, which reads as "we do not know that this was ever fixed" and is the truth.
//
// Every open episode for a recovered component closes, whatever its subject. The component is the thing an operator restores (they
// re-activate the extension, not one provider inside it), so its recovery ends every fault reported under it.
//
// snapshotAtNs is the report's own time and is the ordering guard. host_health is last-writer-wins on it, so a delayed snapshot
// that lost that race did NOT update the stored component states, and acting on it here would resolve an episode from a reading the
// current health row already rejected.
//
// The guard reads the stored value in the same statement as the update rather than tracking the upsert's outcome in Go, so it is
// not defeated by two replicas interleaving their upserts. It is a FILTER and not a lock: two check-ins for one host racing inside
// this statement can still both pass it, in which case the newer one's resolution is the one that lands or the older writes a
// resolution a moment before the newer overwrites nothing (the row is no longer open). Both outcomes stamp a real observed instant,
// which is the property that matters; serialising them would mean a lock on the check-in path for a case that costs at most a few
// seconds of accuracy.
//
// An empty recovered set closes nothing and does not query.
func (s *Store) CloseHealthEpisodes(
	ctx context.Context, hostID string, recovered []api.RecoveredComponent, snapshotAtNs int64,
) (int64, error) {
	if len(recovered) == 0 {
		return 0, nil
	}
	// Each recovered component contributes a (component, instant) pair, and an episode closes only if its component recovered AT OR
	// AFTER the episode opened. A component whose healthy transition predates the fault is not evidence of recovery: it says the
	// component was healthy BEFORE it failed, which is exactly what a delayed pre-fault snapshot looks like when it arrives after the
	// fault event and still happens to be the newest health row. An earlier cut stamped GREATEST(opened_at_ns, instant) instead,
	// which turned that case into a plausible zero-length outage and closed a fault that was still in progress, hiding precisely the
	// host this record exists to surface. Declining to close is the honest answer, and it is the same answer a vanished component
	// gets: we have not been told the fault ended.
	//
	// The same condition keeps a skewed host from recording a negative outage, because a resolution before the opening never
	// satisfies it. The cost is that a host whose clock jumped backwards mid-outage leaves the episode open until it reports a
	// transition past the opening; erring toward "not known to be fixed" is the direction this record already takes.
	var resolution, match strings.Builder
	resolution.WriteString("CASE component")
	setArgs := make([]any, 0, len(recovered)*2)
	whereArgs := make([]any, 0, len(recovered)*2)
	for i, c := range recovered {
		at := c.AtNs
		// A component that reports no transition instant (an older agent, or a state it has held since boot) falls back to the
		// snapshot's own time, which is the freshest instant we can honestly attribute the recovery to. A transition cannot have
		// happened AFTER the snapshot that reports it, so a later one is a malformed or skewed report and is clamped the same way;
		// the service already clamps an implausibly-future reported_at_ns, and this is the per-component equivalent it cannot see.
		if at <= 0 || at > snapshotAtNs {
			at = snapshotAtNs
		}
		resolution.WriteString(" WHEN ? THEN ?")
		setArgs = append(setArgs, c.Type, at)
		if i > 0 {
			match.WriteString(" OR ")
		}
		match.WriteString("(component = ? AND opened_at_ns <= ?)")
		whereArgs = append(whereArgs, c.Type, at)
	}
	resolution.WriteString(" END")

	query := `
		UPDATE host_health_episodes
		SET resolved_at_ns = ` + resolution.String() + `
		WHERE host_id = ?
		  AND resolved_at_ns IS NULL
		  AND (` + match.String() + `)
		  AND ? >= COALESCE((SELECT reported_at_ns FROM host_health WHERE host_id = ?), 0)`
	inArgs := make([]any, 0, len(setArgs)+len(whereArgs)+3)
	inArgs = append(inArgs, setArgs...)
	inArgs = append(inArgs, hostID)
	inArgs = append(inArgs, whereArgs...)
	inArgs = append(inArgs, snapshotAtNs, hostID)
	res, err := s.db.ExecContext(ctx, query, inArgs...)
	if err != nil {
		return 0, fmt.Errorf("close host health episodes: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("close host health episodes rows affected: %w", err)
	}
	return n, nil
}
