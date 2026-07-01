package mysql

import (
	"context"
	"database/sql/driver"
	"fmt"
)

// UpsertHostHealth stores the latest agent health snapshot for hostID, last-writer-wins by reportedAtNs. The IF/GREATEST guard makes a
// delayed or out-of-order post (an agent retry, or a slower replica replaying an older snapshot) unable to clobber a fresher one already
// recorded: overall_status and components are replaced only when the incoming reported_at_ns is at least the stored one, while
// reported_at_ns itself moves monotonically forward. components is the driver.Value produced by api.Components.Value(): a JSON []byte,
// or nil for SQL NULL when the snapshot carried no components. VALUES() in the ON DUPLICATE KEY UPDATE clause matches the enrollments
// upsert style in store.go (deprecated in MySQL 8.0.20 but still supported; the codebase keeps one idiom).
func (s *Store) UpsertHostHealth(ctx context.Context, hostID, overallStatus string, components driver.Value, reportedAtNs int64) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO host_health (host_id, overall_status, components, reported_at_ns)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			overall_status = IF(VALUES(reported_at_ns) >= reported_at_ns, VALUES(overall_status), overall_status),
			components     = IF(VALUES(reported_at_ns) >= reported_at_ns, VALUES(components), components),
			reported_at_ns = GREATEST(reported_at_ns, VALUES(reported_at_ns))
	`, hostID, overallStatus, components, reportedAtNs)
	if err != nil {
		return fmt.Errorf("upsert host health: %w", err)
	}
	return nil
}
