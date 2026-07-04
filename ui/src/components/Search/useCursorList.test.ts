import { describe, it, expect, vi } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";

import { useCursorList, type CursorPage } from "./useCursorList";

function pager(pages: CursorPage<number>[]): (cursor: string) => Promise<CursorPage<number>> {
  // Serve pages in order: the first call (empty cursor) returns pages[0], then each subsequent call returns the next.
  let i = 0;
  return () => {
    const p = pages[Math.min(i, pages.length - 1)];
    i += 1;
    return Promise.resolve(p);
  };
}

describe("useCursorList", () => {
  it("fetches the first page and exposes rows + total", async () => {
    const fp = pager([{ rows: [1, 2], nextCursor: "c1", total: 5 }]);
    const { result } = renderHook(() => useCursorList("k", fp));
    await waitFor(() => { expect(result.current.loading).toBe(false); });
    expect(result.current.rows).toEqual([1, 2]);
    expect(result.current.total).toBe(5);
    expect(result.current.hasMore).toBe(true);
  });

  it("appends the next page on loadMore and clears hasMore at the end", async () => {
    const fp = pager([
      { rows: [1, 2], nextCursor: "c1", total: 4 },
      { rows: [3, 4], nextCursor: "", total: 4 },
    ]);
    const { result } = renderHook(() => useCursorList("k", fp));
    await waitFor(() => { expect(result.current.rows).toEqual([1, 2]); });
    act(() => { result.current.loadMore(); });
    await waitFor(() => { expect(result.current.rows).toEqual([1, 2, 3, 4]); });
    expect(result.current.hasMore).toBe(false);
  });

  it("resets and refetches when the key changes", async () => {
    const fetchPage = vi.fn(pager([{ rows: [9], total: 1 }]));
    const { result, rerender } = renderHook(({ k }) => useCursorList(k, fetchPage), {
      initialProps: { k: "a" },
    });
    await waitFor(() => { expect(result.current.rows).toEqual([9]); });
    rerender({ k: "b" });
    await waitFor(() => { expect(result.current.loading).toBe(false); });
    // Two first-page fetches (one per key), each with the empty cursor.
    expect(fetchPage).toHaveBeenCalledTimes(2);
    expect(fetchPage).toHaveBeenNthCalledWith(2, "");
  });

  it("surfaces a fetch error", async () => {
    const fp = () => Promise.reject(new Error("boom"));
    const { result } = renderHook(() => useCursorList("k", fp));
    await waitFor(() => { expect(result.current.error).toBe("boom"); });
    expect(result.current.rows).toEqual([]);
  });
});
