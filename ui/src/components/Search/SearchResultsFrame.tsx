import type { ReactNode } from "react";
import { EmptyState } from "../ui/Table";
import { Button } from "../ui/Button";

interface Props {
  readonly loading: boolean;
  readonly error: string | null;
  // count is the number of rows currently shown; total is the full match count (total_matched) the endpoint reported.
  readonly count: number;
  readonly total: number;
  readonly hasMore: boolean;
  readonly onLoadMore: () => void;
  // emptyLabel is the mode's "nothing matched" message; prompt (optional) short-circuits to a call-to-action shown instead of running
  // a search (the event modes need an artifact value before they can query, so they render a prompt rather than an empty result).
  readonly emptyLabel: string;
  readonly prompt?: ReactNode;
  // children is the mode's result table, rendered only when there are rows.
  readonly children: ReactNode;
}

// SearchResultsFrame is the shared result shell for every search mode (issue #582): it owns the prompt / error / searching / empty /
// count / load-more states so each mode supplies only its table. Driven by the useCursorList state a mode passes down.
export function SearchResultsFrame({ loading, error, count, total, hasMore, onLoadMore, emptyLabel, prompt, children }: Props) {
  if (prompt !== undefined && prompt !== null) return <EmptyState>{prompt}</EmptyState>;
  if (error) return <EmptyState>Error: {error}</EmptyState>;
  if (loading && count === 0) return <EmptyState>Searching...</EmptyState>;
  if (count === 0) return <EmptyState>{emptyLabel}</EmptyState>;

  return (
    <>
      <p className="search-page__count">
        Showing {count.toLocaleString()} of {total.toLocaleString()} matches
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
