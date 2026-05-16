package mysql

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fleetdm/edr/server/detection/api"
)

// ListHosts returns a summary of all hosts that have sent events.
func (s *Store) ListHosts(ctx context.Context) ([]api.HostSummary, error) {
	var hosts []api.HostSummary
	err := s.db.SelectContext(ctx, &hosts, `
		SELECT host_id, event_count, last_seen_ns
		FROM hosts
		ORDER BY last_seen_ns DESC`)
	if err != nil {
		return nil, fmt.Errorf("query hosts: %w", err)
	}
	return hosts, nil
}

// CountOfflineHosts returns how many rows in `hosts` have `last_seen_ns` at or before (now - threshold). Used by the OTel
// `edr.offline.hosts` gauge. The `<=` boundary matches HostList.tsx's predicate so the UI pill and gauge agree on hosts seen exactly
// at the cutoff. A host with last_seen_ns == 0 (never seen) counts as offline.
func (s *Store) CountOfflineHosts(ctx context.Context, threshold time.Duration) (int, error) {
	cutoff := time.Now().Add(-threshold).UnixNano()
	var n int
	if err := s.db.GetContext(ctx, &n, `
		SELECT COUNT(*) FROM hosts WHERE last_seen_ns <= ?
	`, cutoff); err != nil {
		return 0, fmt.Errorf("count offline hosts: %w", err)
	}
	return n, nil
}

// UpdateHostLastSeen bumps `hosts.last_seen_ns` to `now.UnixNano()`
// for hostID. Used by detection.Service.RecordHostSeen, which
// response calls from GET /api/commands so the 5-second commander
// poll doubles as a liveness heartbeat. The GREATEST guard stops a
// clock-skewed request from regressing an already-observed fresher
// timestamp.
//
// The INSERT path handles the "host enrolled but never sent events"
// case so the hosts row exists and the UI can render the host even
// before ingest touches it.
func (s *Store) UpdateHostLastSeen(ctx context.Context, hostID string, now time.Time) error {
	ts := now.UnixNano()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO hosts (host_id, event_count, last_seen_ns)
		VALUES (?, 0, ?)
		ON DUPLICATE KEY UPDATE
			last_seen_ns = GREATEST(last_seen_ns, VALUES(last_seen_ns))
	`, hostID, ts)
	if err != nil {
		return fmt.Errorf("update host last_seen %s: %w", hostID, err)
	}
	return nil
}

// UpsertHosts incrementally updates the hosts summary table for a
// batch of ingested events. It aggregates event counts and max
// timestamps per host, then upserts every host in a single batched
// statement.
//
// Issue #91: the prior shape was one ExecContext per distinct host_id
// in the batch — N round-trips inside the ingest hot path. The
// multi-row VALUES clause folds that to one round-trip. The (host_id,
// event_count, last_seen_ns) per-host triple is unique within a
// single call (we aggregate into byHost first), so ON DUPLICATE KEY
// UPDATE only ever fires against pre-existing rows, never against
// rows from earlier in the same VALUES list.
func (s *Store) UpsertHosts(ctx context.Context, events []api.Event) error {
	if len(events) == 0 {
		return nil
	}

	type hostStats struct {
		count   int64
		maxTSNs int64
	}
	byHost := make(map[string]*hostStats)
	for _, e := range events {
		st, ok := byHost[e.HostID]
		if !ok {
			st = &hostStats{}
			byHost[e.HostID] = st
		}
		st.count++
		if e.TimestampNs > st.maxTSNs {
			st.maxTSNs = e.TimestampNs
		}
	}

	placeholders := make([]string, 0, len(byHost))
	args := make([]any, 0, len(byHost)*3)
	for hostID, st := range byHost {
		placeholders = append(placeholders, "(?, ?, ?)")
		args = append(args, hostID, st.count, st.maxTSNs)
	}

	stmt := `INSERT INTO hosts (host_id, event_count, last_seen_ns) VALUES ` +
		strings.Join(placeholders, ", ") + `
		ON DUPLICATE KEY UPDATE
			event_count = event_count + VALUES(event_count),
			last_seen_ns = GREATEST(last_seen_ns, VALUES(last_seen_ns))`

	if _, err := s.db.ExecContext(ctx, stmt, args...); err != nil {
		return fmt.Errorf("upsert hosts (n=%d): %w", len(byHost), err)
	}
	return nil
}
