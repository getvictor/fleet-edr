package mysql

import (
	"context"
	"fmt"

	"github.com/fleetdm/edr/server/detection/api"
	detectionslices "github.com/fleetdm/edr/server/detection/internal/slices"
)

// MonitorRecord is one monitor-mode finding to keep (issue #994): the row an alert would have been, and the events that triggered it.
type MonitorRecord struct {
	Alert    api.Alert
	EventIDs []string
}

// monitorRecordsPerChunk bounds how many monitor records are written together: one archive read for their triggering events, then one
// transaction. It bounds the archive query, the evidence held in memory, and how long the transaction holds its row locks, for a batch
// with many findings. Each chunk is still one read and one commit for many records, which is where the per-record path spent its time.
const monitorRecordsPerChunk = 100

// InsertMonitorRecords keeps a batch's monitor records together (issue #1011): for each chunk of records, one archive read for the union
// of their triggering events, then their rows, event links and evidence copies in one transaction.
//
// A record takes exactly what InsertAlert writes for it, as a monitor record: the same row and dedup key, the same links and evidence,
// and no webhook delivery. A failure returns an error for the caller to retry the batch. Chunks committed before it stay, and the
// dedup key makes the retry's write of them a no-op, which is what one InsertAlert per record already relied on.
func (s *Store) InsertMonitorRecords(ctx context.Context, records []MonitorRecord) error {
	prepared := make([]MonitorRecord, len(records))
	for i, r := range records {
		r.Alert.Disposition = api.AlertDispositionMonitor
		a, err := normalizeAlert(r.Alert)
		if err != nil {
			return err
		}
		prepared[i] = MonitorRecord{Alert: a, EventIDs: detectionslices.Deduplicate(r.EventIDs)}
	}
	for start := 0; start < len(prepared); start += monitorRecordsPerChunk {
		if err := s.insertMonitorRecordChunk(ctx, prepared[start:min(start+monitorRecordsPerChunk, len(prepared))]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) insertMonitorRecordChunk(ctx context.Context, chunk []MonitorRecord) error {
	var eventIDs []string
	for _, r := range chunk {
		eventIDs = append(eventIDs, r.EventIDs...)
	}
	// Read before the transaction opens, for the reason InsertAlert gives: a slow archive must not hold row locks.
	found, err := s.archive.EventsByIDs(ctx, detectionslices.Deduplicate(eventIDs))
	if err != nil {
		return fmt.Errorf("read event payloads for monitor records: %w", err)
	}
	evidence := make(map[string]api.Event, len(found))
	for _, ev := range found {
		evidence[ev.EventID] = ev
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for monitor records: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var links []alertEventLink
	var payloads []alertEventPayload
	for _, r := range chunk {
		id, _, err := insertAlertRow(ctx, tx, r.Alert)
		if err != nil {
			return err
		}
		for _, eid := range r.EventIDs {
			links = append(links, alertEventLink{alertID: id, eventID: eid})
			if ev, ok := evidence[eid]; ok {
				payloads = append(payloads, alertEventPayload{alertID: id, event: ev})
			}
		}
	}
	// INSERT IGNORE for every link: a record matched by its dedup key already holds some of them, and a fresh one cannot collide.
	if err := insertAlertEventLinks(ctx, tx, links, true); err != nil {
		return err
	}
	if err := insertEventPayloads(ctx, tx, payloads); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit monitor records: %w", err)
	}
	return nil
}
