package mysql

import (
	"context"
	"fmt"
	"strings"

	"github.com/fleetdm/edr/server/detection/api"
)

// The kernel code-signing status bits the signing filter interprets, matching ui/src/signing.ts (CS_VALID / CS_ADHOC in
// <kern/cs_blobs.h>). The classification below mirrors deriveSigningVerdict's decision order exactly so a server-side signing filter
// and the UI's node verdict agree on every process.
const (
	csValidFlag = 0x1
	csAdhocFlag = 0x2
)

// searchProcessColumns is the shared projection for the search, matching api.Process's db tags (same set GetProcessTree selects).
const searchProcessColumns = `id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash, pidversion,
	fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns, exit_ingested_at_ns, exit_reason, exit_code,
	previous_exec_id, is_snapshot, last_seen_ns`

// SearchProcesses runs the fleet-wide process search (issue #582): the filter's non-empty predicates ANDed in SQL, ordered
// newest-first by (fork_time_ns, id), keyset-paged from cursor. It returns up to limit rows, a next cursor when a further page
// exists, and total_matched (the full filtered count, independent of the page) for a filtered search, or api.TotalNotCounted for the
// fully-unfiltered fleet browse (the COUNT is skipped there; see the count block below). An empty cursor starts at the newest row; a
// malformed cursor is a caller error surfaced by decodeCursor.
//
// Keyset over the compound (fork_time_ns, id): fork_time_ns alone is not unique, so the row id breaks ties and the pair gives a
// total order. `(fork_time_ns, id) < (?, ?)` in row-value form means "strictly older than the last row of the previous page",
// which stays correct as new rows are ingested at the head between page requests (unlike OFFSET, which would skip or repeat).
func (s *Store) SearchProcesses(ctx context.Context, filter api.ProcessSearchFilter, cursor string, limit int) (api.ProcessSearchResult, error) {
	// Clamp defensively so the store is safe against a bad internal caller: limit+1 fetch and the rows[limit-1] cursor pick below
	// both assume limit >= 1, independent of the handler's own clamp.
	if limit < 1 {
		limit = 1
	}
	where, args := buildSearchWhere(filter)

	// Count only when a filter is set. buildSearchWhere emits just the "1=1" sentinel for the fully-unfiltered fleet browse, and a
	// COUNT(*) over the whole processes table is its most expensive half for a total of only marginal value on a browse (pagination
	// rides the cursor, not the total). Any predicate (even a lone host_id or time window, whose count is index-cheap and answers "how
	// many match") restores the exact count. Mirrors the event search's recent-events skip.
	total := api.TotalNotCounted
	if len(where) > 1 {
		var counted int64
		if err := s.db.GetContext(ctx, &counted,
			"SELECT COUNT(*) FROM processes WHERE "+strings.Join(where, " AND "), args...); err != nil {
			return api.ProcessSearchResult{}, fmt.Errorf("count matched processes: %w", err)
		}
		total = counted
	}

	// The keyset predicate is appended only for pages after the first; it narrows the same filtered set to rows older than the
	// cursor. Kept out of the COUNT above so total_matched reflects the whole set, not the remaining tail.
	pageWhere := append([]string(nil), where...)
	pageArgs := append([]any(nil), args...)
	if cursor != "" {
		c, err := decodeCursor(cursor)
		if err != nil {
			return api.ProcessSearchResult{}, err
		}
		// Row-value comparison expresses "strictly older than the cursor row" over the compound key directly, so the optimizer can
		// range-scan idx_processes_fork_id instead of evaluating an OR chain.
		pageWhere = append(pageWhere, "(fork_time_ns, id) < (?, ?)")
		pageArgs = append(pageArgs, c.forkTimeNs, c.id)
	}

	// Fetch one extra row: its presence tells us another page exists without a second query, and it becomes the next cursor.
	pageArgs = append(pageArgs, limit+1)
	var rows []api.Process
	query := "SELECT " + searchProcessColumns + " FROM processes WHERE " +
		strings.Join(pageWhere, " AND ") + " ORDER BY fork_time_ns DESC, id DESC LIMIT ?"
	if err := s.db.SelectContext(ctx, &rows, query, pageArgs...); err != nil {
		return api.ProcessSearchResult{}, fmt.Errorf("search processes: %w", err)
	}

	result := api.ProcessSearchResult{TotalMatched: total}
	if len(rows) > limit {
		last := rows[limit-1]
		result.NextCursor = encodeCursor(searchCursor{forkTimeNs: last.ForkTimeNs, id: last.ID})
		rows = rows[:limit]
	}
	result.Rows = rows
	return result, nil
}

// buildSearchWhere turns the filter into SQL predicates + args. It always emits at least "1=1" so callers can join with AND and the
// COUNT/SELECT share one predicate set. Every predicate is parameterized; nothing is string-interpolated from caller input.
func buildSearchWhere(filter api.ProcessSearchFilter) ([]string, []any) {
	where := []string{"1=1"}
	var args []any
	if filter.HostID != "" {
		where = append(where, "host_id = ?")
		args = append(args, filter.HostID)
	}
	if filter.Path != "" {
		where = append(where, `path LIKE ? ESCAPE '\\'`)
		args = append(args, "%"+escapeLike(filter.Path)+"%")
	}
	if filter.Hash != "" {
		where = append(where, "sha256 = ?")
		args = append(args, filter.Hash)
	}
	if filter.UID != nil {
		where = append(where, "uid = ?")
		args = append(args, *filter.UID)
	}
	if filter.FromNs > 0 {
		where = append(where, "fork_time_ns >= ?")
		args = append(args, filter.FromNs)
	}
	if filter.ToNs > 0 {
		where = append(where, "fork_time_ns <= ?")
		args = append(args, filter.ToNs)
	}
	if filter.ExitReason != "" {
		where = append(where, "exit_reason = ?")
		args = append(args, filter.ExitReason)
	}
	if pred, ok := signingClassSQL(filter.Signing); ok {
		where = append(where, pred)
	}
	return where, args
}

// Signing-class SQL fragments over the code_signing JSON, built once and composed below so no predicate literal repeats. Each uses
// COALESCE so a missing or partial JSON key (e.g. an empty {} block) takes a definite default rather than NULL (which would make
// every comparison NULL/false and silently drop the row). fmt formats the static CS_* bitmasks in once; there is no caller input here.
var (
	csValid    = fmt.Sprintf("(COALESCE(CAST(JSON_EXTRACT(code_signing, '$.flags') AS UNSIGNED), 0) & %d) <> 0", csValidFlag)
	csAdhoc    = fmt.Sprintf("(COALESCE(CAST(JSON_EXTRACT(code_signing, '$.flags') AS UNSIGNED), 0) & %d) <> 0", csAdhocFlag)
	csTeam     = "COALESCE(JSON_UNQUOTE(JSON_EXTRACT(code_signing, '$.team_id')), '')"
	csSID      = "COALESCE(JSON_UNQUOTE(JSON_EXTRACT(code_signing, '$.signing_id')), '')"
	csPlatform = "COALESCE(CAST(JSON_EXTRACT(code_signing, '$.is_platform_binary') AS UNSIGNED), 0) = 1"
	// csValidNoTeam is the shared prefix for the classes deriveSigningVerdict reaches after ruling out invalid, ad-hoc, and a team
	// id: a block that passed AMFI, is not ad-hoc, and carries no team. platform / signed / unsigned then split off it by the
	// platform flag and the signing id.
	csValidNoTeam = "(" + csValid + " AND NOT " + csAdhoc + " AND " + csTeam + " = '')"
)

// signingClassSQL maps a signer class to a predicate mirroring deriveSigningVerdict's decision order (ui/src/signing.ts): no block
// (or a residual block with no signing id) is unsigned; a cleared CS_VALID bit is invalid; then ad-hoc, then a team id is
// developer-id, then the platform flag, then a signing-id-only residual is signed. The classes are mutually exclusive by
// construction, so the server filter partitions rows the same way the UI labels a node. The unsigned class additionally requires an
// exec, since a fork-only row has no signature to judge (matching the UI's fork-only suppression).
// csHasBlock is the shared prefix of every signer-class predicate that requires a present code-signing block; extracted so the literal
// is defined once (SonarCloud go:S1192).
const csHasBlock = "(code_signing IS NOT NULL AND "

func signingClassSQL(class string) (string, bool) {
	switch class {
	case "unsigned":
		return "(exec_time_ns IS NOT NULL AND (code_signing IS NULL OR (" +
			csValidNoTeam + " AND NOT (" + csPlatform + ") AND " + csSID + " = '')))", true
	case "invalid":
		return csHasBlock + "NOT " + csValid + ")", true
	case "ad-hoc":
		return csHasBlock + csValid + " AND " + csAdhoc + ")", true
	case "developer-id":
		return csHasBlock + csValid + " AND NOT " + csAdhoc + " AND " + csTeam + " <> '')", true
	case "platform":
		return csHasBlock + csValidNoTeam + " AND (" + csPlatform + "))", true
	case "signed":
		return csHasBlock + csValidNoTeam + " AND NOT (" + csPlatform + ") AND " + csSID + " <> '')", true
	default:
		return "", false
	}
}

// escapeLike neutralizes the LIKE metacharacters in a user-supplied substring so a path filter of "a_b" matches the literal
// underscore rather than any character. The query uses the default backslash escape.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
