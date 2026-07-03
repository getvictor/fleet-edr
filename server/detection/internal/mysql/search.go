package mysql

import (
	"context"
	"fmt"
	"strings"

	"github.com/fleetdm/edr/server/detection/api"
)

// csAdhocFlag is the kernel CS_ADHOC status bit (CS_ADHOC in <kern/cs_blobs.h>), the same bit the UI's deriveSigningVerdict reads.
// Kept in sync with ui/src/signing.ts CS_ADHOC; the signing filter below classifies over the code_signing JSON using it.
const csAdhocFlag = 0x2

// searchProcessColumns is the shared projection for the search, matching api.Process's db tags (same set GetProcessTree selects).
const searchProcessColumns = `id, host_id, pid, ppid, path, args, uid, gid, code_signing, sha256, cdhash, pidversion,
	fork_time_ns, fork_ingested_at_ns, exec_time_ns, exit_time_ns, exit_ingested_at_ns, exit_reason, exit_code,
	previous_exec_id, is_snapshot, last_seen_ns`

// SearchProcesses runs the fleet-wide process search (issue #582): the filter's non-empty predicates ANDed in SQL, ordered
// newest-first by (fork_time_ns, id), keyset-paged from cursor. It returns up to limit rows, a next cursor when a further page
// exists, and total_matched (the full filtered count, independent of the page). An empty cursor starts at the newest row; a
// malformed cursor is a caller error surfaced by decodeCursor.
//
// Keyset over the compound (fork_time_ns, id): fork_time_ns alone is not unique, so the row id breaks ties and the pair gives a
// total order. `(fork_time_ns, id) < (?, ?)` in row-value form means "strictly older than the last row of the previous page",
// which stays correct as new rows are ingested at the head between page requests (unlike OFFSET, which would skip or repeat).
func (s *Store) SearchProcesses(ctx context.Context, filter api.ProcessSearchFilter, cursor string, limit int) (api.ProcessSearchResult, error) {
	where, args := buildSearchWhere(filter)

	var total int64
	if err := s.db.GetContext(ctx, &total,
		"SELECT COUNT(*) FROM processes WHERE "+strings.Join(where, " AND "), args...); err != nil {
		return api.ProcessSearchResult{}, fmt.Errorf("count matched processes: %w", err)
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
		pageWhere = append(pageWhere, "(fork_time_ns < ? OR (fork_time_ns = ? AND id < ?))")
		pageArgs = append(pageArgs, c.forkTimeNs, c.forkTimeNs, c.id)
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
		where = append(where, "path LIKE ?")
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
	if pred, sarg, ok := signingPredicate(filter.Signing); ok {
		where = append(where, pred)
		args = append(args, sarg...)
	}
	return where, args
}

// signingPredicate expresses a signer-class filter over the code_signing JSON, matching deriveSigningVerdict's decision order so the
// server filter and the UI verdict agree. Returns ok=false for an empty or unrecognized class (no constraint added).
func signingPredicate(class string) (string, []any, bool) {
	switch class {
	case "unsigned":
		// No code_signing block, or a block carrying no identity, reads unsigned (mirrors deriveSigningVerdict's null + empty-id cases).
		return "(code_signing IS NULL OR (JSON_UNQUOTE(JSON_EXTRACT(code_signing, '$.signing_id')) = '' " +
			"AND JSON_UNQUOTE(JSON_EXTRACT(code_signing, '$.team_id')) = ''))", nil, true
	case "ad-hoc":
		return "(code_signing IS NOT NULL AND (JSON_EXTRACT(code_signing, '$.flags') & ?) <> 0)", []any{csAdhocFlag}, true
	case "developer-id":
		return "(code_signing IS NOT NULL AND (JSON_EXTRACT(code_signing, '$.flags') & ?) = 0 " +
			"AND JSON_UNQUOTE(JSON_EXTRACT(code_signing, '$.team_id')) <> '')", []any{csAdhocFlag}, true
	case "platform":
		return "(code_signing IS NOT NULL AND (JSON_EXTRACT(code_signing, '$.flags') & ?) = 0 " +
			"AND JSON_UNQUOTE(JSON_EXTRACT(code_signing, '$.team_id')) = '' " +
			"AND JSON_EXTRACT(code_signing, '$.is_platform_binary') = true)", []any{csAdhocFlag}, true
	case "signed":
		return "(code_signing IS NOT NULL AND (JSON_EXTRACT(code_signing, '$.flags') & ?) = 0 " +
			"AND JSON_UNQUOTE(JSON_EXTRACT(code_signing, '$.team_id')) = '' " +
			"AND JSON_EXTRACT(code_signing, '$.is_platform_binary') = false " +
			"AND JSON_UNQUOTE(JSON_EXTRACT(code_signing, '$.signing_id')) <> '')", []any{csAdhocFlag}, true
	default:
		return "", nil, false
	}
}

// escapeLike neutralizes the LIKE metacharacters in a user-supplied substring so a path filter of "a_b" matches the literal
// underscore rather than any character. The query uses the default backslash escape.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
