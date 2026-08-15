package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/telemetryhealth"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// ListHosts returns a summary of all hosts that have sent events. The LEFT JOINs reach into the endpoint context's `enrollments` and
// `host_health` tables (same MySQL database, keyed on the shared host_id) to decorate each row with the enrollment hostname and OS
// version and the agent-health rollup. LEFT so a host that has sent events but never enrolled or never posted health still returns;
// COALESCE folds the outer-join NULLs into "" (strings) and HostHealthUnknown (rollup) so the scan targets stay plain strings.
func (s *Store) ListHosts(ctx context.Context) ([]api.HostSummary, error) {
	var hosts []api.HostSummary
	err := s.db.SelectContext(ctx, &hosts, `
		SELECT h.host_id, COALESCE(e.hostname, '') AS hostname, COALESCE(e.os_version, '') AS os_version,
		       COALESCE(e.platform, '') AS platform,
		       h.event_count, h.last_seen_ns, COALESCE(hh.overall_status, ?) AS overall_status
		FROM hosts h
		LEFT JOIN enrollments e ON e.host_id = h.host_id
		LEFT JOIN host_health hh ON hh.host_id = h.host_id
		ORDER BY h.last_seen_ns DESC`, api.HostHealthUnknown)
	if err != nil {
		return nil, fmt.Errorf("query hosts: %w", err)
	}
	// Fold in the conditions the server derives from telemetry the host cannot self-report on (issue #677), so the list badge and
	// the host page cannot disagree about the same host. One archive query for the whole page, not one per row.
	//
	// Only candidate hosts are asked about. A host already reporting a fault cannot gain a derived condition whatever its telemetry
	// says, so including it would buy an answer that is thrown away, and on a fleet where something is broadly wrong that is most of
	// the list.
	hostIDs := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if telemetryhealth.CanDerive(h.OverallStatus) {
			hostIDs = append(hostIDs, h.HostID)
		}
	}
	activity := s.telemetryActivity(ctx, hostIDs)
	for i, h := range hosts {
		derived := telemetryhealth.Derive(h.OverallStatus, activity[h.HostID])
		hosts[i].OverallStatus = telemetryhealth.Rollup(h.OverallStatus, derived)
	}
	return hosts, nil
}

// derivedFor returns the derived conditions for a single host, reading the archive only when the host is a candidate for one.
//
// The guard is the point: without it, every host page load of an already-unhealthy host would spend an archive query to compute a
// result that is discarded, which is the single-host mirror of the filter ListHosts applies to its page.
func (s *Store) derivedFor(ctx context.Context, hostID, reportedStatus string) []api.DerivedComponent {
	if !telemetryhealth.CanDerive(reportedStatus) {
		return nil
	}
	return telemetryhealth.Derive(reportedStatus, s.telemetryActivity(ctx, []string{hostID})[hostID])
}

// telemetryActivityHostCap bounds how many hosts one derived-health read asks the archive about.
//
// Sized well past the product's stated target (10-500 endpoint pilots) so it is not reached in practice, and present only so that
// the bound exists at all: this read hangs off an unpaginated list endpoint, and an argument list that grows with the fleet is a
// property worth ruling out on the page an operator loads most.
const telemetryActivityHostCap = 2000

// telemetryActivity reads the per-host telemetry freshness backing the derived health conditions.
//
// A failure is logged and swallowed, returning nil. That is a deliberate asymmetry: this signal is an ENRICHMENT of the hosts list
// and the host health detail, and taking either page down because the event archive is unreachable would trade a rare, low-severity
// missed signal for a total loss of the operator's primary view, at exactly the moment (an infrastructure problem) they most need it.
// Callers index the nil map freely; a missing entry is the zero activity, which derives nothing.
func (s *Store) telemetryActivity(ctx context.Context, hostIDs []string) map[string]visibilityapi.TelemetryActivity {
	if len(hostIDs) == 0 {
		return nil
	}
	if len(hostIDs) > telemetryActivityHostCap {
		// Bound the fan-in rather than growing one IN clause with the fleet. The hosts list is unpaginated, so this read's argument
		// count would otherwise track fleet size on the operator's primary page; the enrichment is not worth an unbounded query.
		// Truncation is logged because a silently-enriched prefix would read as "every host is fine" for the hosts left out.
		s.logger.WarnContext(ctx, "derive telemetry health: host count over cap, enriching the first hosts only",
			"hosts", len(hostIDs), "cap", telemetryActivityHostCap)
		hostIDs = hostIDs[:telemetryActivityHostCap]
	}
	activity, err := s.archive.TelemetryActivityForHosts(ctx, hostIDs, telemetryhealth.Windows(s.now()))
	if err != nil {
		s.logger.WarnContext(ctx, "derive telemetry health: archive read failed, serving reported health only",
			"hosts", len(hostIDs), "err", err)
		return nil
	}
	return activity
}

// HostDetail returns the single-host identity + liveness view for the host page header (issue #579). Same cross-context posture as
// ListHosts: FROM hosts (an unknown id is sql.ErrNoRows, which the handler maps to 404), LEFT JOINs into the endpoint context's
// enrollments and host_health so a host that has sent events but never enrolled or never checked in still returns, with COALESCEd
// empty identity and an unknown rollup. enrolled_at converts to UnixNano in SQL (UNIX_TIMESTAMP handles the session-timezone
// conversion for the TIMESTAMP column) so the scan target stays a plain int64 in the codebase's ns convention.
func (s *Store) HostDetail(ctx context.Context, hostID string) (api.HostDetail, error) {
	var d api.HostDetail
	err := s.db.GetContext(ctx, &d, `
		SELECT h.host_id,
		       COALESCE(e.hostname, '')      AS hostname,
		       COALESCE(e.platform, '')      AS platform,
		       COALESCE(e.os_name, '')       AS os_name,
		       COALESCE(e.os_version, '')    AS os_version,
		       COALESCE(e.os_build, '')      AS os_build,
		       COALESCE(e.agent_version, '') AS agent_version,
		       COALESCE(e.source_ip, '')     AS source_ip,
		       CAST(COALESCE(UNIX_TIMESTAMP(e.enrolled_at), 0) * 1000000000 AS SIGNED) AS enrolled_at_ns,
		       COALESCE(e.inventory_reported_at_ns, 0) AS inventory_reported_at_ns,
		       h.event_count, h.last_seen_ns,
		       COALESCE(hh.overall_status, ?) AS overall_status
		FROM hosts h
		LEFT JOIN enrollments e ON e.host_id = h.host_id
		LEFT JOIN host_health hh ON hh.host_id = h.host_id
		WHERE h.host_id = ?`, api.HostHealthUnknown, hostID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return api.HostDetail{}, err
		}
		return api.HostDetail{}, fmt.Errorf("query host detail: %w", err)
	}
	// Same fold as ListHosts, for the same reason applied one level down: three endpoints expose a field called overall_status, and
	// two of them meaning "effective" while this one meant "as reported" is exactly the kind of difference that survives review and
	// then loses the signal the first time a UI reads the header's rollup instead of the health detail's.
	d.OverallStatus = telemetryhealth.Rollup(d.OverallStatus, s.derivedFor(ctx, hostID, d.OverallStatus))
	return d, nil
}

// HostHealth returns the operator-facing agent-health detail for one host, reading the endpoint context's `host_health` table (same
// database, shared host_id). A host with no recorded snapshot is not an error: it returns OverallStatus HostHealthUnknown with null
// Components, matching how ListHosts COALESCEs the missing row, so the detail view renders "unknown" rather than 404ing a real host
// that simply has not checked in health yet.
func (s *Store) HostHealth(ctx context.Context, hostID string) (api.HostHealth, error) {
	var h api.HostHealth
	err := s.db.GetContext(ctx, &h, `
		SELECT overall_status, reported_at_ns, components
		FROM host_health
		WHERE host_id = ?`, hostID)
	if errors.Is(err, sql.ErrNoRows) {
		// No snapshot means no claim to contradict, so the derived check is skipped entirely rather than run against an unknown
		// rollup: Derive would reject it anyway, and not asking spares the archive a query per never-checked-in host.
		return api.HostHealth{OverallStatus: api.HostHealthUnknown}, nil
	}
	if err != nil {
		return api.HostHealth{}, fmt.Errorf("query host health: %w", err)
	}
	h.DerivedComponents = s.derivedFor(ctx, hostID, h.OverallStatus)
	h.OverallStatus = telemetryhealth.Rollup(h.OverallStatus, h.DerivedComponents)
	return h, nil
}

// histogramTargetBuckets bounds how many bars a window produces: the bucket size is the window divided by this, floored to whole
// seconds (minimum 1s), so a 1h window yields 1-minute buckets and a 7d window yields ~2.8h buckets.
const histogramTargetBuckets = 60

// ceilDiv returns ceil(a/b) for positive a and b.
func ceilDiv(a, b int64) int64 {
	return (a + b - 1) / b
}

// ActivityHistogram counts process starts per time bucket over [fromNs, toNs) for the host page's activity strip (issue #581). A
// pure GROUP BY over fork_time_ns: starts, not tree-overlap rows, so long-lived processes do not smear across every bucket and no
// join is needed. Buckets are sparse (only non-empty ones return); Total is their sum by construction.
func (s *Store) ActivityHistogram(ctx context.Context, hostID string, fromNs, toNs int64) (api.ActivityHistogram, error) {
	window := toNs - fromNs
	// Bucket = the per-bar target (window / 60) rounded UP to a whole second, so the bar count never exceeds the target: flooring a
	// target in [1s, 2s) (a 60-120s window) back to 1s would double the bar count for that band, breaking the bounded-count
	// guarantee. ceilDiv both times; a 1s floor covers sub-minute windows.
	sec := int64(time.Second)
	perBucket := ceilDiv(window, histogramTargetBuckets)
	bucketNs := max(ceilDiv(perBucket, sec)*sec, sec)
	var rows []api.ActivityBucket
	err := s.db.SelectContext(ctx, &rows, `
		SELECT ? + ((fork_time_ns-?) DIV ?) * ? AS start_ns, COUNT(*) AS count
		FROM processes
		WHERE host_id = ? AND fork_time_ns >= ? AND fork_time_ns < ?
		GROUP BY start_ns
		ORDER BY start_ns`, fromNs, fromNs, bucketNs, bucketNs, hostID, fromNs, toNs)
	if err != nil {
		return api.ActivityHistogram{}, fmt.Errorf("query activity histogram: %w", err)
	}
	out := api.ActivityHistogram{BucketNs: bucketNs, Buckets: rows}
	for _, b := range rows {
		out.Total += b.Count
	}
	return out, nil
}

// CountOfflineHosts returns how many rows in `hosts` have `last_seen_ns` at or before the cutoff (now minus threshold). Used by the OTel
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
// in the batch: N round-trips inside the ingest hot path. The
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
