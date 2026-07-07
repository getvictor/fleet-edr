import type { ReactNode } from "react";
import { EmptyState } from "../ui/Table";
import { Button } from "../ui/Button";

interface Props {
  readonly loading: boolean;
  readonly error: string | null;
  // count is the number of rows currently shown; total is the full match count (total_matched) the endpoint reported, or negative when
  // the endpoint deliberately skipped the count (the recent-events browse), in which case only the shown count is displayed.
  readonly count: number;
  readonly total: number;
  readonly hasMore: boolean;
  readonly onLoadMore: () => void;
  // emptyLabel is the mode's "nothing matched" message.
  readonly emptyLabel: string;
  // children is the mode's result table, rendered only when there are rows.
  readonly children: ReactNode;
}

// SearchResultsFrame is the shared result shell for every search mode (issue #582): it owns the error / searching / empty / count /
// load-more states so each mode supplies only its table. Driven by the useCursorList state a mode passes down. An error with no rows
// replaces the table; an error with rows already shown (e.g. a failed "Load more") renders inline above them so the operator keeps the
// results they had and can retry, rather than losing the page to a full error state.
export function SearchResultsFrame({ loading, error, count, total, hasMore, onLoadMore, emptyLabel, children }: Props) {
  if (count === 0) {
    if (error) return <EmptyState>Error: {error}</EmptyState>;
    if (loading) return <EmptyState>Searching...</EmptyState>;
    return <EmptyState>{emptyLabel}</EmptyState>;
  }

  return (
    <>
      {error && <p className="search-page__error" role="alert">Error: {error}</p>}
      <p className="search-page__count">
        {total < 0
          ? `Showing ${count.toLocaleString()}`
          : `Showing ${count.toLocaleString()} of ${total.toLocaleString()} matches`}
      </p>
      {children}
      {hasMore && (
        <div className="search-page__more">
          <Button size="small" variant="inverse" onClick={onLoadMore} disabled={loading}>
            {loading ? "Loading..." : "Load more"}
          </Button>
        </div>
      )}
    </>
  );
}
