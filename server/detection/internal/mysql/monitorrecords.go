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

// monitorRecordsPerTransaction bounds how many monitor records one transaction writes, so a batch with many findings holds its row
// locks for a bounded time. Each transaction is still one commit for many records, which is where the per-record path spent its time.
const monitorRecordsPerTransaction = 100

// InsertMonitorRecords keeps a batch's monitor records together (issue #1011): one archive read for the union of their triggering
// events, then each chunk's rows, event links and evidence copies in one transaction.
//
// A record takes exactly what InsertAlert writes for it, as a monitor record: the same row and dedup key, the same links and evidence,
// and no webhook delivery. A failure returns an error for the caller to retry the batch. Chunks committed before it stay, and the
// dedup key makes the retry's write of them a no-op, which is what one InsertAlert per record already relied on.
func (s *Store) InsertMonitorRecords(ctx context.Context, records []MonitorRecord) error {
	prepared := make([]MonitorRecord, len(records))
	var allEventIDs []string
	for i, r := range records {
		r.Alert.Disposition = api.AlertDispositionMonitor
		a, err := normalizeAlert(r.Alert)
		if err != nil {
			return err
		}
		eventIDs := detectionslices.Deduplicate(r.EventIDs)
		prepared[i] = MonitorRecord{Alert: a, EventIDs: eventIDs}
		allEventIDs = append(allEventIDs, eventIDs...)
	}
	// Read before any transaction opens, for the reason InsertAlert gives: a slow archive must not hold row locks.
	evidence, err := s.archive.EventsByIDs(ctx, detectionslices.Deduplicate(allEventIDs))
	if err != nil {
		return fmt.Errorf("read event payloads for monitor records: %w", err)
	}
	byID := make(map[string]api.Event, len(evidence))
	for _, ev := range evidence {
		byID[ev.EventID] = ev
	}
	for start := 0; start < len(prepared); start += monitorRecordsPerTransaction {
		if err := s.insertMonitorRecordChunk(ctx, prepared[start:min(start+monitorRecordsPerTransaction, len(prepared))], byID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) insertMonitorRecordChunk(ctx context.Context, chunk []MonitorRecord, evidence map[string]api.Event) error {
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
