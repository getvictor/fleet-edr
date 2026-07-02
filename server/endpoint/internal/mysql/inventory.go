package mysql

import (
	"context"
	"fmt"
)

// InventoryUpdate carries the self-reported host identity a status check-in wants written onto the enrollment row. A mysql-local
// mirror of api.Inventory so this package keeps taking plain values rather than importing the wire DTO (the same decoupling
// UpsertHostHealth applies by taking a driver.Value).
type InventoryUpdate struct {
	Hostname     string
	OSName       string
	OSVersion    string
	OSBuild      string
	AgentVersion string
}

// UpdateInventory refreshes the enrollment row's identity fields from a status check-in, last-writer-wins by reportedAtNs (the same
// guard UpsertHostHealth uses, expressed as a WHERE clause since this is an UPDATE of an existing row: a host always enrolls before it
// can check in, so a missing row means a revoked-and-purged host and the update is deliberately a no-op). MySQL skips the physical
// write when every value is unchanged, so the once-a-minute check-in cadence does not churn the table.
func (s *Store) UpdateInventory(ctx context.Context, hostID string, inv InventoryUpdate, reportedAtNs int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE enrollments
		SET hostname = ?, os_name = ?, os_version = ?, os_build = ?, agent_version = ?, inventory_reported_at_ns = ?
		WHERE host_id = ? AND inventory_reported_at_ns <= ?
	`, inv.Hostname, inv.OSName, inv.OSVersion, inv.OSBuild, inv.AgentVersion, reportedAtNs, hostID, reportedAtNs)
	if err != nil {
		return fmt.Errorf("update inventory: %w", err)
	}
	return nil
}
