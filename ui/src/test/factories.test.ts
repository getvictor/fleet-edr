import { describe, it, expect } from "vitest";
import type { ProcessNode } from "../types";
import { treeResponse } from "./factories";

// The factory's default metadata has to be a response the server could actually have produced, otherwise every test that uses it is
// asserting against an impossible shape. `returned` means the process ROWS the server's limit admitted, which is not the node count:
// descendants are rows, and an aggregated node stands for its whole group.

function node(id: number, path: string, children?: ProcessNode[]): ProcessNode {
  return { id, host_id: "h1", pid: id, ppid: 1, path, fork_time_ns: 1, children };
}

describe("treeResponse", () => {
  it("defaults to an untruncated response whose counts agree", () => {
    const res = treeResponse([node(1, "/sbin/launchd")]);
    expect(res.truncated).toBe(false);
    expect(res.returned).toBe(res.total_matched);
  });

  it("counts descendants, not just roots", () => {
    const forest = [node(1, "/sbin/launchd", [node(2, "/bin/bash", [node(3, "/usr/bin/curl")])])];
    expect(treeResponse(forest).returned).toBe(3);
  });

  it("counts an aggregated node as its whole group", () => {
    const grep: ProcessNode = {
      ...node(-10, "/usr/bin/grep"),
      aggregated: { count: 12, exited_count: 11, running_count: 1, first_fork_ns: 1, last_fork_ns: 9, sample: [] },
    };
    expect(treeResponse([node(1, "/sbin/launchd", [grep])]).returned).toBe(13);
  });

  it("does not double-count an expanded aggregated node's materialized sample", () => {
    // buildVisibleRoots re-parents an expanded group's capped sample under `children` while keeping `aggregated` set. The group size
    // already covers those members, so the walk must stop at the aggregated node rather than adding its sample on top.
    const expanded: ProcessNode = {
      ...node(-10, "/usr/bin/grep"),
      aggregated: {
        count: 12,
        exited_count: 11,
        running_count: 1,
        first_fork_ns: 1,
        last_fork_ns: 9,
        sample: [node(11, "/usr/bin/grep"), node(12, "/usr/bin/grep")],
      },
      children: [node(11, "/usr/bin/grep"), node(12, "/usr/bin/grep")],
    };
    expect(treeResponse([expanded]).returned).toBe(12);
  });

  it("lets a caller override the metadata to model a truncated read", () => {
    const res = treeResponse([node(1, "/sbin/launchd")], { returned: 2000, total_matched: 2588, truncated: true });
    expect(res).toMatchObject({ returned: 2000, total_matched: 2588, truncated: true });
    expect(res.roots).toHaveLength(1);
  });
});
