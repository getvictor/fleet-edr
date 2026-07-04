import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { SearchResultsFrame } from "./SearchResultsFrame";

const table = <table><tbody><tr><td>a-row</td></tr></tbody></table>;

function frame(over: Partial<Parameters<typeof SearchResultsFrame>[0]> = {}) {
  const props = {
    loading: false,
    error: null as string | null,
    count: 1,
    total: 1,
    hasMore: false,
    onLoadMore: vi.fn(),
    emptyLabel: "Nothing here.",
    children: table,
    ...over,
  };
  return { props, ...render(<SearchResultsFrame {...props} />) };
}

describe("SearchResultsFrame", () => {
  it("shows the prompt and nothing else when a prompt is set", () => {
    frame({ prompt: "Type something", count: 0 });
    expect(screen.getByText("Type something")).toBeInTheDocument();
    expect(screen.queryByText("a-row")).not.toBeInTheDocument();
  });

  it("shows a full-page error when there are no rows", () => {
    frame({ error: "boom", count: 0 });
    expect(screen.getByText("Error: boom")).toBeInTheDocument();
    expect(screen.queryByText("a-row")).not.toBeInTheDocument();
  });

  it("shows Searching... while loading with no rows", () => {
    frame({ loading: true, count: 0 });
    expect(screen.getByText("Searching...")).toBeInTheDocument();
  });

  it("shows the empty label when a completed search matched nothing", () => {
    frame({ count: 0 });
    expect(screen.getByText("Nothing here.")).toBeInTheDocument();
  });

  it("keeps the rows and shows the error inline when a load-more fails", () => {
    // The Copilot finding: an error with rows already shown (failed "Load more") must not replace the table.
    frame({ error: "load more failed", count: 3, total: 10, hasMore: true });
    expect(screen.getByText("a-row")).toBeInTheDocument(); // rows preserved
    expect(screen.getByRole("alert")).toHaveTextContent("Error: load more failed"); // error shown inline
    expect(screen.getByText(/Showing 3 of 10 matches/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Load more" })).toBeInTheDocument(); // retry still available
  });

  it("invokes onLoadMore when the control is clicked and hides it when no more remain", () => {
    const onLoadMore = vi.fn();
    frame({ count: 2, total: 5, hasMore: true, onLoadMore });
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    expect(onLoadMore).toHaveBeenCalledTimes(1);
  });

  it("omits the load-more control when there is no next page", () => {
    frame({ count: 2, total: 2, hasMore: false });
    expect(screen.queryByRole("button", { name: "Load more" })).not.toBeInTheDocument();
  });
});
