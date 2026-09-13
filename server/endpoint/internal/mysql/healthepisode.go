package mysql

import (
	"context"
	"fmt"

	"github.com/fleetdm/edr/server/endpoint/api"
)

// Store is the recorder the detection engine depends on. Asserted here so a signature drift on either side is a compile error in
// this package rather than a wiring failure at boot.
var _ api.HealthEpisodeRecorder = (*Store)(nil)

// OpenHealthEpisode opens an episode for a component fault, and reports whether this call is what opened it.
//
// Idempotence is the schema's job, not this function's. `host_health_episodes` carries a generated column that is 1 while the
// episode is open and NULL once it closes, under a unique key on (host_id, component, kind, open_episode), so an INSERT for a
// fault that already has an open episode collides and INSERT IGNORE drops it. Doing it that way rather than with a read-then-write
// matters because the write path is concurrent across replicas: a SELECT-then-INSERT would let two ingest workers handling two
// reports of one outage both observe "no open episode" and both insert, recording one outage as two.
//
// The returned flag is what a caller logs or counts on: the fault is re-asserted for as long as it lasts, so "opened" is the rare
// edge worth a log line while "already open" is the steady state and must stay silent.
func (s *Store) OpenHealthEpisode(ctx context.Context, e api.HealthEpisode) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT IGNORE INTO host_health_episodes
			(host_id, component, kind, severity, title, description, detail, opened_at_ns)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, e.HostID, e.Component, e.Kind, e.Severity, e.Title, e.Description, e.Detail, e.OpenedAtNs)
	if err != nil {
		return false, fmt.Errorf("open host health episode: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("open host health episode rows affected: %w", err)
	}
	return n > 0, nil
}

// CloseHealthEpisodes closes hostID's open episodes for the components named in recovered, stamping resolvedAtNs, and returns how
// many it closed.
//
// Driven by the status check-in because that is the only moment the server learns a component recovered, and the check-in already
// carries the full component list.
//
// recovered is the components the snapshot reports HEALTHY, and the match is positive on purpose. Closing on the complement (every
// component not currently reporting a fault) would also close the episode of a component that has vanished from the snapshot
// entirely, and that is a resolution nobody observed: an agent that stops reporting a component has not told us the fault ended, so
// stamping an end time would be inventing the one number the record exists to provide. An episode for a component that stops being
// reported stays open, which reads as "we do not know that this was ever fixed" and is the truth.
//
// An empty recovered set closes nothing and does not query.
func (s *Store) CloseHealthEpisodes(ctx context.Context, hostID string, recovered []string, resolvedAtNs int64) (int64, error) {
	if len(recovered) == 0 {
		return 0, nil
	}
	query := `
		UPDATE host_health_episodes
		SET resolved_at_ns = ?
		WHERE host_id = ? AND resolved_at_ns IS NULL AND component IN (?` + repeatPlaceholders(len(recovered)-1) + `)`
	args := make([]any, 0, len(recovered)+2)
	args = append(args, resolvedAtNs, hostID)
	for _, c := range recovered {
		args = append(args, c)
	}
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("close host health episodes: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("close host health episodes rows affected: %w", err)
	}
	return n, nil
}

// repeatPlaceholders returns n further `, ?` placeholders, for an IN list whose first placeholder the caller already wrote. Built
// here rather than with sqlx.In because the count is small and known and there is no slice to expand into a named query.
func repeatPlaceholders(n int) string {
	out := make([]byte, 0, n*3)
	for range n {
		out = append(out, ',', ' ', '?')
	}
	return string(out)
}
