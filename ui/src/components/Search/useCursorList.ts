import { useCallback, useEffect, useRef, useState } from "react";

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

  // generation bumps on every key change; a fetch captures the generation live at call time and its result is applied only while
  // that generation is still current. This drops not just a superseded first page but an in-flight loadMore whose key has since
  // changed, so a slow page-2 response can never append the old filter's rows onto the new filter's results.
  const generation = useRef(0);

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

  // Reset and fetch the first page on key change. Bumping the generation invalidates any fetch (first page OR loadMore) started under
  // the previous key, so a rapid filter change cannot land an older result set.
  useEffect(() => {
    generation.current += 1;
    const gen = generation.current;
    /* eslint-disable react-hooks/set-state-in-effect */
    setRows([]);
    setNextCursor(undefined);
    /* eslint-enable react-hooks/set-state-in-effect */
    load("", () => generation.current !== gen);
  }, [key, load]);

  const loadMore = useCallback(() => {
    if (nextCursor === undefined || loading) return;
    const gen = generation.current;
    load(nextCursor, () => generation.current !== gen);
  }, [nextCursor, loading, load]);

  return { rows, total, loading, error, hasMore: nextCursor !== undefined, loadMore };
}
