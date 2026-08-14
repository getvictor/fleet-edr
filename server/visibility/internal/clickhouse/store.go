// Package clickhouse is the ClickHouse implementation of the visibility context's EventArchive: the durable, append-mostly event lake
// (ADR-0015), the source of truth for per-process correlation and (in v0.5.0) hunting. It backs the `events` table.
//
// Payload is stored as raw JSON text with the hot fields materialized for filtering (pid today); the native ClickHouse JSON type and
// more typed columns are a v0.5.0 hunting optimization. Writes use the native batch protocol; reads use FINAL so at-least-once
// re-deliveries collapsed by ReplacingMergeTree never surface as duplicates.
package clickhouse

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "github.com/ClickHouse/clickhouse-go/v2" // registers the "clickhouse" database/sql driver
	"github.com/XSAM/otelsql"
	"github.com/jmoiron/sqlx"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/visibility/api"
)

// Open dials the ClickHouse event archive through the same otelsql wrapper MySQL uses (server/bootstrap.OpenDB), so every archive
// query and insert gets a span plus the connection-pool / db.sql.* RED metrics with no bespoke code (ADR-0006, OTel only). dsn is a
// clickhouse-go DSN, e.g. "clickhouse://default:@127.0.0.1:9000/edr". Closing the handle is the caller's responsibility.
func Open(ctx context.Context, dsn string) (*sqlx.DB, error) {
	sqldb, err := otelsql.Open("clickhouse", dsn, otelsql.WithAttributes(semconv.DBSystemNameClickHouse))
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}
	if _, err := otelsql.RegisterDBStatsMetrics(sqldb, otelsql.WithAttributes(semconv.DBSystemNameClickHouse)); err != nil {
		if cerr := sqldb.Close(); cerr != nil {
			return nil, fmt.Errorf("register clickhouse stats metrics: %w (close: %w)", err, cerr)
		}
		return nil, fmt.Errorf("register clickhouse stats metrics: %w", err)
	}
	db := sqlx.NewDb(sqldb, "clickhouse")
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}
	return db, nil
}

// Store is the ClickHouse-backed EventArchive. It holds the connection pool opened by Open; closing it is the caller's responsibility.
type Store struct {
	db *sqlx.DB
}

// Compile-time check that Store satisfies the published EventArchive contract.
var _ api.EventArchive = (*Store)(nil)

// New returns a Store wrapping db. Schema is applied separately via visibility/bootstrap.ApplySchema.
func New(db *sqlx.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("visibility clickhouse.New: db handle must not be nil")
	}
	return &Store{db: db}, nil
}

// Insert durably stores events in the archive using ClickHouse's native batch protocol (one prepared INSERT, a row per event, one
// committed block). Idempotent by event_id: ReplacingMergeTree(ingested_at_ns) collapses a re-inserted event to its latest version on
// merge, and reads use FINAL, so at-least-once delivery never surfaces a duplicate. Events are stored with the IngestedAtNs the caller
// already stamped; the archive does not re-stamp.
func (s *Store) Insert(ctx context.Context, events []api.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin clickhouse batch: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO events (event_id, host_id, timestamp_ns, ingested_at_ns, event_type, platform, payload)")
	if err != nil {
		return fmt.Errorf("prepare clickhouse insert: %w", err)
	}
	defer stmt.Close() //nolint:errcheck
	for i := range events {
		payload := []byte(events[i].Payload)
		if len(payload) == 0 {
			payload = []byte("null") // events.payload is non-empty JSON text; an empty envelope stores as the JSON null literal
		}
		// Pass the payload bytes directly; the clickhouse-go driver binds []byte to a String column without the extra string copy.
		if _, err := stmt.ExecContext(ctx, events[i].EventID, events[i].HostID, events[i].TimestampNs,
			events[i].IngestedAtNs, events[i].EventType, events[i].Platform, payload); err != nil {
			return fmt.Errorf("append clickhouse row %s: %w", events[i].EventID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit clickhouse batch: %w", err)
	}
	return nil
}

// NetworkEventsForProcess returns the network_connect and dns_query events attributed to (hostID, pid) within tr, ordered by
// timestamp. FINAL collapses ReplacingMergeTree duplicates so a re-delivered event is not double-counted. The filter mirrors the
// detection correlation read it replaces: server-stamped ingested_at_ns bounds the window (clock-drift tolerant) and pid is the
// materialized column extracted from the payload.
func (s *Store) NetworkEventsForProcess(ctx context.Context, hostID string, pid int, tr httpserver.TimeRange) ([]api.Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, host_id, timestamp_ns, ingested_at_ns, event_type, platform, payload
		FROM events FINAL
		WHERE host_id = ? AND event_type IN ('network_connect', 'dns_query') AND pid = ?
		  AND ingested_at_ns >= ? AND ingested_at_ns <= ?
		ORDER BY timestamp_ns`, hostID, pid, tr.FromNs, tr.ToNs)
	if err != nil {
		return nil, fmt.Errorf("clickhouse network events for process: %w", err)
	}
	return scanEvents(rows)
}

// EventsByTypeForHost returns one host's events of a single type within the event-time range tr, oldest first. FINAL collapses
// ReplacingMergeTree duplicates. The WHERE clause is the table's sorting-key prefix (host_id, event_type, timestamp_ns), so this is
// a primary-key range scan.
//
// event_id breaks timestamp ties, matching EventsByIDs. Without it two events sharing a timestamp come back in an order the engine
// does not control, so a row cap could keep a different subset run to run.
//
// The row cap is not defensive padding: events are agent-supplied, so the number of rows a host can put inside any window is
// controlled by the host, and an unbounded scan here would let one misbehaving or hostile agent turn a rule's correlation read into
// an arbitrarily large result. The cap is far above what a real window holds (the caller's is seconds wide and its event type is
// emitted on state CHANGES), so truncation cannot be reached by honest traffic.
//
// Reaching it is an ERROR, not a truncated page. The caller decides from what is absent, so handing it a silently shortened result
// would let a host that emitted enough events to bury its own recovery be reported as tampered with. One row beyond the cap is
// fetched purely to detect the overflow.
func (s *Store) EventsByTypeForHost(ctx context.Context, hostID, eventType string, tr httpserver.TimeRange) ([]api.Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, host_id, timestamp_ns, ingested_at_ns, event_type, platform, payload
		FROM events FINAL
		WHERE host_id = ? AND event_type = ? AND timestamp_ns >= ? AND timestamp_ns <= ?
		ORDER BY timestamp_ns, event_id
		LIMIT ?`, hostID, eventType, tr.FromNs, tr.ToNs, eventsByTypeRowCap+1)
	if err != nil {
		return nil, fmt.Errorf("clickhouse events by type for host: %w", err)
	}
	events, err := scanEvents(rows)
	if err != nil {
		return nil, err
	}
	if len(events) > eventsByTypeRowCap {
		return nil, fmt.Errorf("clickhouse events by type for host %s (%s): %w", hostID, eventType, api.ErrEventsTruncated)
	}
	return events, nil
}

// eventsByTypeRowCap bounds EventsByTypeForHost. See the method comment for why a cap exists at all.
const eventsByTypeRowCap = 1000

// placeholders returns n comma-separated bind markers for an IN clause, e.g. "?, ?, ?". Callers append the matching arguments in the
// same order. n must be positive; every caller here returns early on an empty set, since "IN ()" is not valid SQL.
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

// TelemetryActivityForHosts counts each telemetry stream per host over the two nested windows in one pass.
//
// One query, not one per host and not one per window: the whole read is a single scan of the reference range with conditional
// aggregates, so adding hosts widens the key filter rather than multiplying round trips. That is what lets the Hosts list derive the
// signal for every row it returns at the cost of one query per page.
//
// The scan is key-pruned. The archive's sorting key leads with host_id, so an explicit host list is what makes this a set of key
// ranges rather than a time-filtered scan of the whole fleet; the reference bound then prunes granules within each host's range by
// the timestamp_ns min/max index.
//
// No FINAL: see TelemetryActivity for why duplicate rows cannot change any decision made from these counts.
func (s *Store) TelemetryActivityForHosts(
	ctx context.Context, hostIDs []string, w api.TelemetryActivityWindows,
) (map[string]api.TelemetryActivity, error) {
	if len(hostIDs) == 0 {
		return map[string]api.TelemetryActivity{}, nil
	}
	// Argument order follows the placeholders left to right: the three conditional aggregates each take the inner window's start,
	// then the host key filter, then the reference bounds.
	args := make([]any, 0, len(hostIDs)+5)
	args = append(args, w.SilentFromNs, w.SilentFromNs, w.SilentFromNs)
	for _, id := range hostIDs {
		args = append(args, id)
	}
	args = append(args, w.Reference.FromNs, w.Reference.ToNs)
	rows, err := s.db.QueryContext(ctx, `
		SELECT host_id,
		       countIf(event_type IN ('exec', 'fork') AND timestamp_ns >= ?)     AS process_in_window,
		       countIf(event_type = 'network_connect' AND timestamp_ns >= ?)     AS connect_in_window,
		       countIf(event_type = 'dns_query' AND timestamp_ns >= ?)           AS dns_in_window,
		       countIf(event_type = 'network_connect')                           AS connect_in_reference,
		       countIf(event_type = 'dns_query')                                 AS dns_in_reference
		FROM events
		WHERE host_id IN (`+placeholders(len(hostIDs))+`) AND timestamp_ns >= ? AND timestamp_ns <= ?
		GROUP BY host_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("clickhouse telemetry activity for hosts: %w", err)
	}
	defer rows.Close()

	out := make(map[string]api.TelemetryActivity, len(hostIDs))
	for rows.Next() {
		var hostID string
		var a api.TelemetryActivity
		if err := rows.Scan(&hostID, &a.ProcessInWindow, &a.ConnectInWindow, &a.DNSInWindow,
			&a.ConnectInReference, &a.DNSInReference); err != nil {
			return nil, fmt.Errorf("clickhouse scan telemetry activity: %w", err)
		}
		out[hostID] = a
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("clickhouse iterate telemetry activity: %w", err)
	}
	return out, nil
}

// EventsByIDs returns the full envelopes for the given event_ids, ordered by (timestamp_ns, event_id). Alert evidence capture snapshots
// a finding's triggering events into alert_event_payloads with it (ADR-0015), so the evidence outlives the archive's retention window.
// FINAL collapses ReplacingMergeTree duplicates; IDs with no surviving event are simply absent from the result, keeping capture
// best-effort. Empty input returns no rows without a query.
func (s *Store) EventsByIDs(ctx context.Context, eventIDs []string) ([]api.Event, error) {
	if len(eventIDs) == 0 {
		return nil, nil
	}
	args := make([]any, len(eventIDs))
	for i, id := range eventIDs {
		args[i] = id
	}
	query := "SELECT event_id, host_id, timestamp_ns, ingested_at_ns, event_type, platform, payload FROM events FINAL WHERE event_id IN (" +
		placeholders(len(eventIDs)) + ") ORDER BY timestamp_ns, event_id"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("clickhouse events by ids: %w", err)
	}
	return scanEvents(rows)
}

// SearchEvents runs the fleet-wide connection/DNS artifact search (issue #582): events of filter.EventType whose materialized artifact
// column equals filter.Value, newest-first, keyset-paged over (timestamp_ns, event_id). FINAL collapses ReplacingMergeTree duplicates.
// Matching the materialized column (not JSONExtract inline) lets the bloom skip index prune granules. total_matched is the full match
// count independent of the page. An empty cursor starts at the newest event.
func (s *Store) SearchEvents(ctx context.Context, filter api.EventSearchFilter, cursor string, limit int) (api.EventSearchResult, error) {
	col, ok := api.ArtifactField(filter.EventType)
	if !ok {
		return api.EventSearchResult{}, fmt.Errorf("clickhouse search: unsupported event type %q", filter.EventType)
	}

	where := []string{"event_type = ?"}
	args := []any{filter.EventType}
	if filter.Value != "" {
		// Exact match on the materialized artifact column so the bloom skip index prunes granules. An empty value lists recent events
		// of this type unfiltered (the ORDER BY prefix on event_type keeps that cheap).
		where = append(where, col+" = ?")
		args = append(args, filter.Value)
	}
	if filter.HostID != "" {
		where = append(where, "host_id = ?")
		args = append(args, filter.HostID)
	}
	if filter.FromNs > 0 {
		where = append(where, "ingested_at_ns >= ?")
		args = append(args, filter.FromNs)
	}
	if filter.ToNs > 0 {
		where = append(where, "ingested_at_ns <= ?")
		args = append(args, filter.ToNs)
	}
	whereSQL := strings.Join(where, " AND ")
	// Count only when narrowing by an artifact (a targeted search, where the bloom-indexed count is cheap and "N of M" answers "how many
	// hosts hit this address"). The recent-events browse (no artifact) skips the count: on a large archive it is the more expensive half
	// of the page for a total of marginal value, and pagination rides NextCursor, not the total.
	return s.pageEventsByKeyset(ctx, whereSQL, args, cursor, limit, filter.Value != "")
}

// HostTimeline returns one host's exec/network_connect/dns_query events interleaved in event-time order, newest-first (issue #583):
// host + event_type IN the requested (or all timeline) classes + timestamp_ns within the window + optional case-insensitive payload
// substring, keyset-paged over (timestamp_ns, event_id). The window bounds event time (timestamp_ns), unlike SearchEvents which bounds
// ingest time. FINAL collapses ReplacingMergeTree duplicates; total_matched is the full match count independent of the page.
func (s *Store) HostTimeline(ctx context.Context, filter api.HostTimelineFilter, cursor string, limit int) (api.EventSearchResult, error) {
	// Intersect with the allowlist (not just default-when-empty) so the store's own contract holds even if a caller passes a
	// non-timeline class like fork; an empty result means only non-timeline classes were requested, so nothing matches.
	types := api.EffectiveTimelineEventTypes(filter.EventTypes)
	if len(types) == 0 {
		return api.EventSearchResult{}, nil
	}
	where := []string{"host_id = ?"}
	args := []any{filter.HostID}
	for _, t := range types {
		args = append(args, t)
	}
	where = append(where, "event_type IN ("+placeholders(len(types))+")")
	if filter.FromNs > 0 {
		where = append(where, "timestamp_ns >= ?")
		args = append(args, filter.FromNs)
	}
	if filter.ToNs > 0 {
		where = append(where, "timestamp_ns <= ?")
		args = append(args, filter.ToNs)
	}
	if filter.Text != "" {
		// Substring over the raw payload matches a path, address, hostname, or query name without per-type field logic; the host +
		// window + type predicate has already pruned the granule set, so the un-indexed scan runs over a bounded slice.
		where = append(where, "positionCaseInsensitiveUTF8(payload, ?) > 0")
		args = append(args, filter.Text)
	}
	if len(filter.Chain) > 0 {
		// Alert-chain scope: keep only events belonging to one of the chain's process generations, matched by (pid, pidversion). pid is
		// materialized (prunes granules); pidversion lives in the payload, extracted per row over that pruned set. The pair is unique
		// across PID reuse, so a later process that reused a chain pid is excluded, and it is robust to ingest timing (unlike a window,
		// which collapses to near-zero for a short-lived process whose fork and exit land in one batch). The JSONHas guard is required
		// because JSONExtractInt returns 0 for a missing field: pidversion 0 is a real kernel generation, so without the guard a scope
		// for (pid, 0) would sweep in legacy events that never carried pidversion. A tuple IN lets ClickHouse hash-match in one pass
		// instead of walking an OR chain per row.
		gens := make([]string, len(filter.Chain))
		for i, g := range filter.Chain {
			gens[i] = "(?, ?)"
			args = append(args, g.PID, g.PIDVersion)
		}
		where = append(where, "(JSONHas(payload, 'pidversion') AND (pid, JSONExtractInt(payload, 'pidversion')) IN ("+strings.Join(gens, ", ")+"))")
	}
	// The host timeline is scoped to one host (host_id is the ORDER BY prefix), so its count is cheap and always reported.
	return s.pageEventsByKeyset(ctx, strings.Join(where, " AND "), args, cursor, limit, true)
}

// pageEventsByKeyset runs the shared newest-first keyset page behind both the fleet-wide search and the host timeline: when countTotal
// it counts every row matching baseWhere/baseArgs (else TotalMatched is TotalNotCounted), then fetches up to limit events strictly
// before the cursor position ordered (timestamp_ns, event_id) DESC, returning a next cursor when more remain. baseWhere is the full
// filter predicate with no cursor clause; baseArgs are its positional args in order. The cursor is decoded before the COUNT so a
// malformed cursor is a cheap 400, not a full count first.
func (s *Store) pageEventsByKeyset(ctx context.Context, baseWhere string, baseArgs []any, cursor string, limit int, countTotal bool) (api.EventSearchResult, error) {
	if limit < 1 {
		limit = 1
	}
	pageWhere := baseWhere
	pageArgs := append([]any(nil), baseArgs...)
	if cursor != "" {
		c, err := api.DecodeEventCursor(cursor)
		if err != nil {
			return api.EventSearchResult{}, err
		}
		pageWhere += " AND (timestamp_ns, event_id) < (?, ?)"
		pageArgs = append(pageArgs, c.TimestampNs, c.EventID)
	}

	total := api.TotalNotCounted
	if countTotal {
		var counted uint64
		if err := s.db.GetContext(ctx, &counted, "SELECT count() FROM events FINAL WHERE "+baseWhere, baseArgs...); err != nil {
			return api.EventSearchResult{}, fmt.Errorf("clickhouse event page count: %w", err)
		}
		total = int64(counted)
	}
	pageArgs = append(pageArgs, limit+1)

	rows, err := s.db.QueryContext(ctx, "SELECT event_id, host_id, timestamp_ns, ingested_at_ns, event_type, platform, payload "+
		"FROM events FINAL WHERE "+pageWhere+" ORDER BY timestamp_ns DESC, event_id DESC LIMIT ?", pageArgs...)
	if err != nil {
		return api.EventSearchResult{}, fmt.Errorf("clickhouse event page: %w", err)
	}
	events, err := scanEvents(rows)
	if err != nil {
		return api.EventSearchResult{}, err
	}

	result := api.EventSearchResult{TotalMatched: total}
	if len(events) > limit {
		last := events[limit-1]
		result.NextCursor = api.EncodeEventCursor(api.EventCursor{TimestampNs: last.TimestampNs, EventID: last.EventID})
		events = events[:limit]
	}
	result.Events = events
	return result, nil
}

// scanEvents drains rows of the standard event projection (event_id, host_id, timestamp_ns, ingested_at_ns, event_type, platform,
// payload) into a slice and closes them. The String payload is scanned into a []byte (database/sql copies the driver's string into it)
// and handed to json.RawMessage, since database/sql cannot assign a string driver value straight into json.RawMessage.
func scanEvents(rows *sql.Rows) ([]api.Event, error) {
	defer rows.Close() //nolint:errcheck
	var events []api.Event
	for rows.Next() {
		var e api.Event
		var payload []byte
		if err := rows.Scan(&e.EventID, &e.HostID, &e.TimestampNs, &e.IngestedAtNs, &e.EventType, &e.Platform, &payload); err != nil {
			return nil, fmt.Errorf("scan clickhouse event: %w", err)
		}
		e.Payload = payload
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan clickhouse events: %w", err)
	}
	return events, nil
}
