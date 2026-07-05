import { describe, it, expect } from "vitest";
import type { ProcessNode } from "../types";
import type { D3Node, D3PointNode } from "./ProcessTree.helpers";
import { chevronGlyph, computeLayoutBounds, nodeDotFill, nodeHasChevron, nodeLabelText } from "./ProcessTree.render";

// node builds a valid ProcessNode from a partial so a test names only the fields it cares about (mirrors ProcessTree.helpers.test.ts).
function node(overrides: Partial<ProcessNode>): ProcessNode {
  return { id: 0, host_id: "h1", pid: 0, ppid: 0, path: "", fork_time_ns: 0, ...overrides };
}

// d3node wraps a ProcessNode in the minimal D3Node shape nodeLabelText reads (name/pid + data).
function d3node(name: string, pid: number, data: ProcessNode): D3Node {
  return { name, pid, path: data.path, data };
}

// pointNode fabricates just the x/y computeLayoutBounds reads; the rest of a real HierarchyPointNode is irrelevant here.
function pointNode(x: number, y: number): D3PointNode {
  return { x, y } as unknown as D3PointNode;
}

const RED = "#ff5c83";
const GREEN = "#009a7d";
const GREY = "#8b8fa2";

describe("computeLayoutBounds", () => {
  it("returns the min/max x and y over all nodes", () => {
    const bounds = computeLayoutBounds([pointNode(3, 10), pointNode(-2, 40), pointNode(7, 5)]);
    expect(bounds).toEqual({ minX: -2, maxX: 7, minY: 5, maxY: 40 });
  });

  it("collapses to the single node when there is one", () => {
    expect(computeLayoutBounds([pointNode(4, 9)])).toEqual({ minX: 4, maxX: 4, minY: 9, maxY: 9 });
  });
});

describe("nodeDotFill", () => {
  it("is red when the node is alerted, regardless of state", () => {
    expect(nodeDotFill(node({ exit_time_ns: 1 }), true)).toBe(RED);
  });

  it("is green for a running (non-exited) process", () => {
    expect(nodeDotFill(node({}), false)).toBe(GREEN);
  });

  it("is grey for an exited process", () => {
    expect(nodeDotFill(node({ exit_time_ns: 123 }), false)).toBe(GREY);
  });

  it("is green for an aggregated group with a running member, grey when all exited", () => {
    const agg = (running: number) => node({
      aggregated: { count: 10, exited_count: 10 - running, running_count: running, first_fork_ns: 1, last_fork_ns: 2 },
    });
    expect(nodeDotFill(agg(3), false)).toBe(GREEN);
    expect(nodeDotFill(agg(0), false)).toBe(GREY);
  });
});

describe("nodeHasChevron", () => {
  it("is always true for an aggregated node (expandable to its sample)", () => {
    expect(nodeHasChevron(node({ aggregated: { count: 2, exited_count: 0, running_count: 2, first_fork_ns: 1, last_fork_ns: 2 } }))).toBe(true);
  });

  it("is true when the node has visible children", () => {
    expect(nodeHasChevron(node({ children: [node({ id: 2 })] }))).toBe(true);
  });

  it("is true for a rendered-collapsed node (has _collapsedCount) even with no children", () => {
    expect(nodeHasChevron(node({ _collapsedCount: 4 }))).toBe(true);
  });

  it("is false for a childless, non-collapsed leaf", () => {
    expect(nodeHasChevron(node({}))).toBe(false);
  });
});

describe("chevronGlyph", () => {
  it("points down when an aggregated node is expanded, right when collapsed", () => {
    const agg = node({ id: 7, aggregated: { count: 2, exited_count: 0, running_count: 2, first_fork_ns: 1, last_fork_ns: 2 } });
    expect(chevronGlyph(agg, new Set([7]))).toBe("▼");
    expect(chevronGlyph(agg, new Set())).toBe("▶");
  });

  it("points right for a rendered-collapsed node, down otherwise", () => {
    expect(chevronGlyph(node({ _collapsedCount: 3 }), new Set())).toBe("▶");
    expect(chevronGlyph(node({}), new Set())).toBe("▼");
  });
});

describe("nodeLabelText", () => {
  it("renders an aggregated node as a group header with its count", () => {
    const agg = node({ aggregated: { count: 1000, exited_count: 1000, running_count: 0, first_fork_ns: 1, last_fork_ns: 2 } });
    expect(nodeLabelText(d3node("grep", 0, agg))).toBe("grep ×1000");
  });

  it("renders a plain node as name (pid)", () => {
    expect(nodeLabelText(d3node("bash", 42, node({ pid: 42 })))).toBe("bash (42)");
  });

  it("appends the hidden-descendant count when a subtree is collapsed", () => {
    expect(nodeLabelText(d3node("bash", 42, node({ pid: 42, _collapsedCount: 5 })))).toBe("bash (42)  +5");
  });
});
