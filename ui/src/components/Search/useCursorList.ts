import { useCallback, useEffect, useState } from "react";

// CursorPage is the shape every keyset-paginated search response shares (issue #582): a page of rows, the opaque cursor for the next
// page (absent/empty on the last), and the full match count independent of the page.
export interface CursorPage<Row> {
  rows: Row[];
  nextCursor?: string;
  total: number;
}

// CursorList is the state a "load more" list exposes: the accumulated rows, the total, loading/error, whether more remain, and the
// loadMore action.
export interface CursorList<Row> {
  rows: Row[];
  total: number;
  loading: boolean;
  error: string | null;
  hasMore: boolean;
  loadMore: () => void;
}

// useCursorList drives a keyset-paginated result: it fetches the first page whenever `key` changes (the serialized filter, so a filter
// change resets and refetches), and loadMore fetches the next page and appends. fetchPage takes the cursor (empty for the first page)
// and returns one CursorPage. The generic Row keeps it reusable across the process and (PR 3b) event search result shapes.
export function useCursorList<Row>(key: string, fetchPage: (cursor: string) => Promise<CursorPage<Row>>): CursorList<Row> {
  const [rows, setRows] = useState<Row[]>([]);
  const [total, setTotal] = useState(0);
  const [nextCursor, setNextCursor] = useState<string | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // load fetches one page: the first page (empty cursor) replaces the rows; a subsequent page appends. A stale response (its request
  // superseded by a newer key or loadMore) is dropped via the cancelled flag the effect/callback install.
  const load = useCallback(
    (cursor: string, cancelled: () => boolean) => {
      setLoading(true);
      setError(null);
      fetchPage(cursor)
        .then((page) => {
          if (cancelled()) return;
          setRows((prev) => (cursor === "" ? page.rows : [...prev, ...page.rows]));
          setTotal(page.total);
          setNextCursor(page.nextCursor && page.nextCursor !== "" ? page.nextCursor : undefined);
        })
        .catch((err: unknown) => {
          if (!cancelled()) setError(err instanceof Error ? err.message : "Unknown error");
        })
        .finally(() => {
          if (!cancelled()) setLoading(false);
        });
    },
    [fetchPage],
  );

  // Reset and fetch the first page on key change. The cancelled flag makes an in-flight first page from a prior key a no-op, so a
  // rapid filter change cannot land an older result set.
  useEffect(() => {
    let cancelled = false;
    /* eslint-disable react-hooks/set-state-in-effect */
    setRows([]);
    setNextCursor(undefined);
    /* eslint-enable react-hooks/set-state-in-effect */
    load("", () => cancelled);
    return () => {
      cancelled = true;
    };
  }, [key, load]);

  const loadMore = useCallback(() => {
    if (nextCursor === undefined || loading) return;
    load(nextCursor, () => false);
  }, [nextCursor, loading, load]);

  return { rows, total, loading, error, hasMore: nextCursor !== undefined, loadMore };
}
