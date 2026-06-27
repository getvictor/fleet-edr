package intake

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/httpserver"
)

// fakeEventArchive records the events handed to Insert and can be made to fail, so the fan-out's archive-first ordering and its
// error handling are testable without a ClickHouse container (the in-memory MemArchive used elsewhere never fails).
type fakeEventArchive struct {
	inserted  [][]api.Event
	insertErr error
}

func (f *fakeEventArchive) Insert(_ context.Context, events []api.Event) error {
	f.inserted = append(f.inserted, events)
	return f.insertErr
}

func (f *fakeEventArchive) NetworkEventsForProcess(context.Context, string, int, httpserver.TimeRange) ([]api.Event, error) {
	return nil, nil
}
func (f *fakeEventArchive) EventsByIDs(context.Context, []string) ([]api.Event, error) {
	return nil, nil
}

// fakeEventLog records the events handed to Append and can be made to fail.
type fakeEventLog struct {
	appended  [][]api.Event
	appendErr error
}

func (f *fakeEventLog) Append(_ context.Context, events []api.Event) error {
	f.appended = append(f.appended, events)
	return f.appendErr
}
func (f *fakeEventLog) Claim(context.Context, int) ([]api.Event, error) { return nil, nil }
func (f *fakeEventLog) Ack(context.Context, []string) error             { return nil }
func (f *fakeEventLog) Nack(context.Context, []string) error            { return nil }
func (f *fakeEventLog) CountPending(context.Context) (int64, error)     { return 0, nil }

// postBatch drives handleIngest directly with host_id pinned the way the HostToken middleware does, so these tests need no DB: the
// store (host-summary + snapshot-freshness writes) is only reached after a successful fan-out, which the error-path cases never hit.
func postBatch(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := endpointapi.WithHostID(context.Background(), "host-a")
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/events", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.IngestHandler().ServeHTTP(rec, req)
	return rec
}

// TestHandleIngest_FanOut pins the ADR-0015 ingest fan-out: archive first, then the work queue, 200 only after both, and a 500 (never
// a partial enqueue) if either store fails. The happy path is covered end-to-end by the integration suite; these cases pin the
// ordering and the two failure branches that an in-memory archive cannot exercise.
func TestHandleIngest_FanOut(t *testing.T) {
	t.Parallel()
	// A fork (stored) plus a snapshot_heartbeat (partitioned out before the fan-out, issue #408), so we can assert the stores see
	// only the storable event.
	const body = `[` +
		`{"event_id":"e-fork","host_id":"host-a","timestamp_ns":1000,"event_type":"fork","payload":{"child_pid":42,"parent_pid":1}},` +
		`{"event_id":"e-hb","host_id":"host-a","timestamp_ns":1001,"event_type":"snapshot_heartbeat","payload":{"pid":42}}` +
		`]`

	t.Run("archive insert failure returns 500 and does not enqueue", func(t *testing.T) {
		t.Parallel()
		archive := &fakeEventArchive{insertErr: errors.New("archive down")}
		queue := &fakeEventLog{}
		h := New(nil, nil, BuildInfo{}, queue, archive)

		rec := postBatch(t, h, body)
		assert.Equal(t, http.StatusInternalServerError, rec.Code, "an archive write failure must not be acknowledged")
		assert.Empty(t, queue.appended, "archive-first: the queue must not be appended when the archive write fails")
	})

	t.Run("eventlog append failure returns 500 after archiving", func(t *testing.T) {
		t.Parallel()
		archive := &fakeEventArchive{}
		queue := &fakeEventLog{appendErr: errors.New("queue down")}
		h := New(nil, nil, BuildInfo{}, queue, archive)

		rec := postBatch(t, h, body)
		assert.Equal(t, http.StatusInternalServerError, rec.Code, "a queue write failure must not be acknowledged")
		require.Len(t, archive.inserted, 1, "the archive is written first, before the queue append is attempted")
		require.Len(t, archive.inserted[0], 1, "heartbeats are partitioned out before the fan-out; only the fork is stored")
		assert.Equal(t, "e-fork", archive.inserted[0][0].EventID)
	})
}
