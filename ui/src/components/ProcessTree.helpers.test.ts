import { describe, it, expect } from "vitest";
import { hierarchy } from "d3";

import {
  isSystemPath,
  countDescendants,
  toD3Hierarchy,
  collectMatches,
  chainWindows,
  findAlertChain,
  resolveAlertEntry,
  selectNodeFromParams,
  viewHref,
  buildPreservedIds,
  buildQueryFilterIds,
  buildVisibleRoots,
  type D3Node,
  type D3PointNode,
  type VisibilityFilters,
} from "./ProcessTree.helpers";
import type { AlertDetail, ProcessNode } from "../types";
import { NANOSECONDS_PER_MILLISECOND } from "../constants";

// node builds a valid ProcessNode from a partial: every required Process field carries a benign default so a test only names the
// fields it cares about (id/pid/path/children/args/fork+exit windows/aggregated).
function node(overrides: Partial<ProcessNode>): ProcessNode {
  return { id: 0, host_id: "h1", pid: 0, ppid: 0, path: "", fork_time_ns: 0, ...overrides };
}

// layout mirrors ProcessTree.tsx's d3 layout step just enough to feed collectMatches: build the D3 hierarchy, then take the flat
// descendant list as point nodes. collectMatches only reads .data and .parent, so the missing x/y from a real tree layout is moot.
function layout(roots: ProcessNode[]): D3PointNode[] {
  return hierarchy<D3Node>(toD3Hierarchy(roots)).descendants() as D3PointNode[];
}

describe("isSystemPath", () => {
  it("flags each system path segment on a substring (not prefix) match", () => {
    expect(isSystemPath("/System/Library/Frameworks/WebKit.framework/WebKit")).toBe(true);
    expect(isSystemPath("/usr/libexec/trustd")).toBe(true);
    expect(isSystemPath("/Library/Apple/System/Library/CoreServices/XProtect")).toBe(true);
    // Cryptex-mounted framework binary: the segment appears mid-path, so substring matching still catches it.
    expect(isSystemPath("/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/WebKit")).toBe(true);
  });

  it("keeps any .app bundle visible even under /System/Library/", () => {
    expect(isSystemPath("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder")).toBe(false);
    expect(isSystemPath("/Applications/Safari.app/Contents/MacOS/Safari")).toBe(false);
  });

  it("returns false for ordinary user and third-party binaries", () => {
    expect(isSystemPath("/usr/local/bin/tool")).toBe(false);
    expect(isSystemPath("/opt/homebrew/bin/curl")).toBe(false);
    expect(isSystemPath("/bin/bash")).toBe(false);
  });
});

describe("countDescendants", () => {
  it("returns 0 for a leaf with no children", () => {
    expect(countDescendants(node({ id: 1 }))).toBe(0);
    expect(countDescendants(node({ id: 1, children: [] }))).toBe(0);
  });

  it("counts every descendant across the full subtree", () => {
    const tree = node({
      id: 1,
      children: [
        node({ id: 2, children: [node({ id: 4 }), node({ id: 5 })] }),
        node({ id: 3, children: [node({ id: 6, children: [node({ id: 7 })] })] }),
      ],
    });
    // 2,3,4,5,6,7 = six descendants.
    expect(countDescendants(tree)).toBe(6);
  });
});

describe("toD3Hierarchy", () => {
  it("returns the single root directly with basename as name and children present", () => {
    const d3n = toD3Hierarchy([
      node({ id: 1, pid: 100, path: "/usr/bin/curl", children: [node({ id: 2, pid: 200, path: "/bin/sh" })] }),
    ]);
    expect(d3n.name).toBe("curl");
    expect(d3n.pid).toBe(100);
    expect(d3n.path).toBe("/usr/bin/curl");
    expect(d3n.children).toHaveLength(1);
    expect(d3n.children?.[0].name).toBe("sh");
  });

  it("falls back to `PID <n>` when the node has no path, and drops the empty children array", () => {
    const d3n = toD3Hierarchy([node({ id: 1, pid: 4242, path: "", children: [] })]);
    expect(d3n.name).toBe("PID 4242");
    // An empty children array is normalized to undefined (kids.length === 0 branch).
    expect(d3n.children).toBeUndefined();
  });

  it("wraps multiple roots under a synthetic root with pid 0", () => {
    const d3n = toD3Hierarchy([
      node({ id: 1, pid: 100, path: "/bin/a" }),
      node({ id: 2, pid: 101, path: "/bin/b" }),
    ]);
    expect(d3n.name).toBe("root");
    expect(d3n.pid).toBe(0);
    expect(d3n.path).toBe("");
    expect(d3n.children?.map((c) => c.pid)).toEqual([100, 101]);
  });
});

describe("collectMatches", () => {
  const roots = [
    node({
      id: 1,
      pid: 100,
      path: "/bin/a",
      children: [
        node({
          id: 2,
          pid: 200,
          path: "/bin/bash",
          args: ["bash", "-c", "evilcmd"],
          children: [node({ id: 3, pid: 300, path: "/usr/bin/curl" })],
        }),
      ],
    }),
  ];

  it("returns empty match + path sets for an empty query", () => {
    const { matches, pathNodes } = collectMatches(layout(roots), "");
    expect(matches).toHaveLength(0);
    expect(pathNodes.size).toBe(0);
  });

  it("matches by name and includes the whole ancestor path", () => {
    const { matches, pathNodes } = collectMatches(layout(roots), "bash");
    expect(matches.map((m) => m.data.pid)).toEqual([200]);
    // The match's ancestors (a -> bash) are collected so the context stays visible.
    expect([...pathNodes].map((n) => n.data.pid).sort((x, y) => x - y)).toEqual([100, 200]);
  });

  it("matches by args, by pid substring, and by path", () => {
    expect(collectMatches(layout(roots), "evilcmd").matches.map((m) => m.data.pid)).toEqual([200]);
    expect(collectMatches(layout(roots), "300").matches.map((m) => m.data.pid)).toEqual([300]);
    // A pid deep match pulls its full chain (a -> bash -> curl) into pathNodes.
    expect([...collectMatches(layout(roots), "300").pathNodes].map((n) => n.data.pid).sort((x, y) => x - y)).toEqual([100, 200, 300]);
    expect(collectMatches(layout(roots), "curl").matches.map((m) => m.data.pid)).toEqual([300]);
    // "usr" appears only in curl's path (/usr/bin/curl), not its basename, so this exercises the path branch on its own.
    expect(collectMatches(layout(roots), "usr").matches.map((m) => m.data.pid)).toEqual([300]);
  });

  it("returns nothing when no node matches", () => {
    const { matches, pathNodes } = collectMatches(layout(roots), "no-such-thing");
    expect(matches).toHaveLength(0);
    expect(pathNodes.size).toBe(0);
  });

  it("skips the synthetic pid-0 root that a multi-root forest inserts", () => {
    const multi = [node({ id: 1, pid: 100, path: "/bin/a" }), node({ id: 2, pid: 101, path: "/bin/b" })];
    // "root" only matches the synthetic node's name; it must be skipped, leaving no matches.
    const { matches } = collectMatches(layout(multi), "root");
    expect(matches).toHaveLength(0);
  });
});

describe("findAlertChain", () => {
  // R(1) -> X(2) -> {X1(4) -> X1a(6), X2(5)}; R(1) -> Y(3) -> Y1(7)
  const roots = [
    node({
      id: 1,
      children: [
        node({
          id: 2,
          children: [node({ id: 4, children: [node({ id: 6 })] }), node({ id: 5 })],
        }),
        node({ id: 3, children: [node({ id: 7 })] }),
      ],
    }),
  ];

  it("returns the target's ancestors plus the target's descendants, excluding unrelated branches", () => {
    const chain = findAlertChain(roots, 4);
    // path R(1)->X(2)->X1(4) plus X1's subtree (4,6). X2(5), Y(3), Y1(7) are off-chain.
    expect([...chain].sort((a, b) => a - b)).toEqual([1, 2, 4, 6]);
  });

  it("returns every id when the target is the root", () => {
    const chain = findAlertChain(roots, 1);
    expect([...chain].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7]);
  });

  it("returns an empty set when the target is not in the tree", () => {
    expect(findAlertChain(roots, 999).size).toBe(0);
  });
});

describe("chainWindows", () => {
  // ids 1 -> 2 -> 3 with ingest lifetimes; id 4 is off-chain. Node 3 is still running (no exit).
  const roots = [
    node({
      id: 1, pid: 100, fork_ingested_at_ns: 10, exit_ingested_at_ns: 20,
      children: [
        node({
          id: 2, pid: 200, fork_ingested_at_ns: 12, exit_ingested_at_ns: 18,
          children: [node({ id: 3, pid: 300, fork_ingested_at_ns: 14 })],
        }),
        node({ id: 4, pid: 400, fork_ingested_at_ns: 11, exit_ingested_at_ns: 19 }),
      ],
    }),
  ];

  it("maps chain node ids to (pid, ingest window), skips off-chain nodes, and gives a running node an open upper bound", () => {
    expect(chainWindows(roots, new Set([1, 2, 3]))).toEqual([
      { pid: 100, fromIngestedNs: 10, toIngestedNs: 20 },
      { pid: 200, fromIngestedNs: 12, toIngestedNs: 18 },
      { pid: 300, fromIngestedNs: 14, toIngestedNs: 0 },
    ]);
  });

  it("falls back to the kernel fork/exit times when ingest stamps are absent (pre-migration rows)", () => {
    const legacy = [node({ id: 1, pid: 5, fork_time_ns: 7, exit_time_ns: 9 })];
    expect(chainWindows(legacy, new Set([1]))).toEqual([{ pid: 5, fromIngestedNs: 7, toIngestedNs: 9 }]);
  });

  it("returns an empty array for an empty id set", () => {
    expect(chainWindows(roots, new Set())).toEqual([]);
  });
});

describe("selectNodeFromParams", () => {
  const roots = [
    node({ id: 1, pid: 1, path: "/sbin/launchd", children: [node({ id: 6, pid: 42, path: "/usr/bin/deep" })] }),
  ];

  it("returns null when there are no roots", () => {
    expect(selectNodeFromParams([], new URLSearchParams("process=1"))).toBeNull();
  });

  it("resolves ?process=<dbId> by walking into children", () => {
    const found = selectNodeFromParams(roots, new URLSearchParams("process=6"));
    expect(found?.id).toBe(6);
    expect(found?.pid).toBe(42);
  });

  it("returns null for a ?process id that is not present", () => {
    expect(selectNodeFromParams(roots, new URLSearchParams("process=999"))).toBeNull();
  });

  it("returns null when neither process nor a pid+at pair is supplied", () => {
    expect(selectNodeFromParams(roots, new URLSearchParams())).toBeNull();
    // pid without at falls through to the final return.
    expect(selectNodeFromParams(roots, new URLSearchParams("pid=1"))).toBeNull();
  });

  it("selects by overrideProcessId (the alert route's entryAlert) in precedence over the params", () => {
    // The /alerts/:alertId route has no ?process= in the URL; it passes the alerted process id directly.
    expect(selectNodeFromParams(roots, new URLSearchParams(), 6)?.id).toBe(6);
    // The override wins even when a ?process= is also present.
    expect(selectNodeFromParams(roots, new URLSearchParams("process=1"), 6)?.id).toBe(6);
  });

  it("ignores a 0 overrideProcessId (a process-optional alert) and falls through to the params", () => {
    expect(selectNodeFromParams(roots, new URLSearchParams(), 0)).toBeNull();
    expect(selectNodeFromParams(roots, new URLSearchParams("process=6"), 0)?.id).toBe(6);
  });

  describe("?pid=<pid>&at=<ms> lifetime windows", () => {
    // Two generations reuse pid 500: gen A [1ms..5ms], gen B [10ms..running].
    const ms = (n: number) => n * NANOSECONDS_PER_MILLISECOND;
    const reuseRoots = [
      node({
        id: 100,
        pid: 9,
        path: "/root",
        children: [
          node({ id: 10, pid: 500, path: "/gen-a", fork_time_ns: ms(1), exit_time_ns: ms(5) }),
          node({ id: 11, pid: 500, path: "/gen-b", fork_time_ns: ms(10) }),
        ],
      }),
    ];

    it("picks the generation whose lifetime brackets the event time", () => {
      // at=3ms is inside gen A only.
      expect(selectNodeFromParams(reuseRoots, new URLSearchParams("pid=500&at=3"))?.id).toBe(10);
      // at=12ms is after gen A exited and inside still-running gen B.
      expect(selectNodeFromParams(reuseRoots, new URLSearchParams("pid=500&at=12"))?.id).toBe(11);
      // at=10ms: gen A exited at 5ms, gen B forked exactly at 10ms (fork <= atNs boundary is inclusive).
      expect(selectNodeFromParams(reuseRoots, new URLSearchParams("pid=500&at=10"))?.id).toBe(11);
    });

    it("prefers the closest fork at/before the anchor when two generations both bracket it", () => {
      const overlapping = [
        node({
          id: 100,
          pid: 9,
          path: "/root",
          children: [
            // Visit order matters for the tiebreak: id10 seeds best, id12 (later fork) replaces it, id13 (earlier fork than the
            // current best) must NOT replace it. This exercises all three outcomes of `best === null || fork > best.fork`.
            node({ id: 10, pid: 500, path: "/older", fork_time_ns: ms(1), exit_time_ns: ms(5) }),
            node({ id: 12, pid: 500, path: "/newest", fork_time_ns: ms(2.5), exit_time_ns: ms(5) }),
            node({ id: 13, pid: 500, path: "/middle", fork_time_ns: ms(1.5), exit_time_ns: ms(5) }),
          ],
        }),
      ];
      // All three bracket at=3ms; the latest fork (id 12) wins regardless of visit order.
      expect(selectNodeFromParams(overlapping, new URLSearchParams("pid=500&at=3"))?.id).toBe(12);
    });

    it("treats exit_time_ns 0 as still-running (not exited at time 0)", () => {
      const running = [node({ id: 20, pid: 600, path: "/running", fork_time_ns: ms(1), exit_time_ns: 0 })];
      expect(selectNodeFromParams(running, new URLSearchParams("pid=600&at=100"))?.id).toBe(20);
    });

    it("returns null when no generation of that pid was alive at the event time", () => {
      // at=0.5ms is before gen A forked (1ms).
      expect(selectNodeFromParams(reuseRoots, new URLSearchParams("pid=500&at=0.5"))).toBeNull();
    });
  });
});

describe("viewHref", () => {
  it("drops ?view= when switching to the default graph view, preserving other params", () => {
    const sp = new URLSearchParams("view=timeline&window=1h");
    expect(viewHref("/hosts/h1", sp, "graph")).toBe("/hosts/h1?window=1h");
  });

  it("sets ?view=timeline while preserving the shared time window", () => {
    const sp = new URLSearchParams("window=1h");
    expect(viewHref("/hosts/h1", sp, "timeline")).toBe("/hosts/h1?window=1h&view=timeline");
  });

  it("emits no query suffix when there are no params", () => {
    expect(viewHref("/hosts/h1", new URLSearchParams(), "graph")).toBe("/hosts/h1");
  });

  it("returns the base path verbatim (the caller passes an already-formed pathname)", () => {
    expect(viewHref("/hosts/a%2Fb%20c", new URLSearchParams(), "graph")).toBe("/hosts/a%2Fb%20c");
  });

  it("toggles the view param on an alert base path, dropping view= for the default graph", () => {
    expect(viewHref("/alerts/842", new URLSearchParams("view=timeline&pid=5"), "graph")).toBe("/alerts/842?pid=5");
  });

  it("does not mutate the caller's URLSearchParams", () => {
    const sp = new URLSearchParams("view=timeline");
    viewHref("/hosts/h1", sp, "graph");
    expect(sp.get("view")).toBe("timeline");
  });
});

describe("buildPreservedIds", () => {
  // R(1) -> A(2) -> B(3); R(1) -> C(4)
  const roots = [
    node({ id: 1, children: [node({ id: 2, children: [node({ id: 3 })] }), node({ id: 4 })] }),
  ];

  it("keeps an alerted node and its full ancestor path, but not unrelated branches", () => {
    const keep = buildPreservedIds(roots, new Set([3]));
    expect([...keep].sort((a, b) => a - b)).toEqual([1, 2, 3]);
  });

  it("keeps only the root when the root itself is alerted", () => {
    expect([...buildPreservedIds(roots, new Set([1]))]).toEqual([1]);
  });

  it("returns an empty set when nothing is alerted", () => {
    expect(buildPreservedIds(roots, new Set()).size).toBe(0);
  });
});

describe("buildQueryFilterIds", () => {
  // R(1,/bin/launchd) -> A(2,/usr/bin/curl args) -> B(3,/bin/sh); R(1) -> C(4,/usr/bin/ssh)
  const roots = [
    node({
      id: 1,
      pid: 1,
      path: "/bin/launchd",
      children: [
        node({
          id: 2,
          pid: 2,
          path: "/usr/bin/curl",
          args: ["curl", "http://evil.example"],
          children: [node({ id: 3, pid: 3, path: "/bin/sh" })],
        }),
        node({ id: 4, pid: 4, path: "/usr/bin/ssh" }),
      ],
    }),
  ];

  it("returns null when the query is empty or whitespace", () => {
    expect(buildQueryFilterIds(roots, "")).toBeNull();
    expect(buildQueryFilterIds(roots, "   ")).toBeNull();
  });

  it("keeps a matching node plus its ancestors (including a non-matching parent) and drops the rest", () => {
    const keep = buildQueryFilterIds(roots, "curl");
    // A(2) matches by name; R(1) is kept as an ancestor even though launchd does not match. B(3), C(4) drop out.
    expect([...(keep ?? new Set())].sort((a, b) => a - b)).toEqual([1, 2]);
  });

  it("matches on args and on a pid substring", () => {
    expect([...(buildQueryFilterIds(roots, "evil") ?? new Set())].sort((a, b) => a - b)).toEqual([1, 2]);
    // pid 3 matches only B(3); the chain R(1)->A(2)->B(3) survives.
    expect([...(buildQueryFilterIds(roots, "3") ?? new Set())].sort((a, b) => a - b)).toEqual([1, 2, 3]);
  });

  it("trims and lowercases the query before matching", () => {
    expect([...(buildQueryFilterIds(roots, "  CURL  ") ?? new Set())].sort((a, b) => a - b)).toEqual([1, 2]);
  });
});

describe("buildVisibleRoots", () => {
  // R(1,/sbin/launchd) -> APP(2,/Applications/Foo.app/...) -> {SYS(3,/System/Library/...) -> LEAF(4,/usr/bin/curl), USER(5,/usr/local/bin/tool)}
  const makeTree = (): ProcessNode[] => [
    node({
      id: 1,
      pid: 1,
      path: "/sbin/launchd",
      children: [
        node({
          id: 2,
          pid: 2,
          path: "/Applications/Foo.app/Contents/MacOS/Foo",
          children: [
            node({
              id: 3,
              pid: 3,
              path: "/System/Library/Frameworks/WebKit.framework/WebKit",
              children: [node({ id: 4, pid: 4, path: "/usr/bin/curl" })],
            }),
            node({ id: 5, pid: 5, path: "/usr/local/bin/tool" }),
          ],
        }),
      ],
    }),
  ];

  const baseFilters = (): VisibilityFilters => ({
    showSystem: true,
    collapsedIds: new Set(),
    expandedAggIds: new Set(),
    preservedIds: new Set(),
    applyCollapse: true,
    alertChainIds: null,
    queryFilterIds: null,
  });

  // childIds pulls the immediate children ids under the first (id 2) grandchild-holder so assertions read clearly.
  const appChildIds = (out: ProcessNode[]): number[] =>
    (out[0].children?.[0].children ?? []).map((c) => c.id).sort((a, b) => a - b);

  it("hides system-path nodes and their subtrees when showSystem is false", () => {
    const out = buildVisibleRoots(makeTree(), { ...baseFilters(), showSystem: false });
    // SYS(3) is a system path so it and its child LEAF(4) drop out; USER(5) survives.
    expect(appChildIds(out)).toEqual([5]);
  });

  it("keeps system-path nodes visible when showSystem is true", () => {
    const out = buildVisibleRoots(makeTree(), baseFilters());
    expect(appChildIds(out)).toEqual([3, 5]);
    // SYS(3) still carries its LEAF child.
    expect(out[0].children?.[0].children?.[0].children?.[0].id).toBe(4);
  });

  it("keeps a preserved system node visible even when showSystem is false", () => {
    const out = buildVisibleRoots(makeTree(), { ...baseFilters(), showSystem: false, preservedIds: new Set([3]) });
    expect(appChildIds(out)).toEqual([3, 5]);
  });

  it("restricts the tree to the alert chain, dropping off-chain nodes", () => {
    const out = buildVisibleRoots(makeTree(), { ...baseFilters(), alertChainIds: new Set([1, 2, 5]) });
    expect(appChildIds(out)).toEqual([5]);
  });

  it("restricts the tree to the query-filter set", () => {
    const out = buildVisibleRoots(makeTree(), { ...baseFilters(), queryFilterIds: new Set([1, 2, 5]) });
    expect(appChildIds(out)).toEqual([5]);
  });

  it("collapses a node's children into a _collapsedCount when applyCollapse is on", () => {
    const out = buildVisibleRoots(makeTree(), { ...baseFilters(), collapsedIds: new Set([2]) });
    const app = out[0].children?.[0];
    expect(app?.children).toBeUndefined();
    // Visible descendants under APP: SYS(3), LEAF(4), USER(5) = 3.
    expect(app?._collapsedCount).toBe(3);
  });

  it("skips the collapse step when applyCollapse is off (search active)", () => {
    const out = buildVisibleRoots(makeTree(), { ...baseFilters(), collapsedIds: new Set([2]), applyCollapse: false });
    const app = out[0].children?.[0];
    expect(app?._collapsedCount).toBeUndefined();
    expect(app?.children?.map((c) => c.id).sort((a, b) => a - b)).toEqual([3, 5]);
  });

  describe("aggregated nodes", () => {
    const aggRoots = (sample?: ProcessNode[]): ProcessNode[] => [
      node({
        id: 6,
        pid: 6,
        path: "/usr/bin/agg",
        aggregated: { count: 10, exited_count: 7, running_count: 3, first_fork_ns: 1, last_fork_ns: 2, sample },
      }),
    ];

    it("materializes the capped sample as children when the aggregate is expanded", () => {
      const sample = [node({ id: 7, pid: 7, path: "/usr/bin/s1" }), node({ id: 8, pid: 8, path: "/usr/bin/s2" })];
      const out = buildVisibleRoots(aggRoots(sample), { ...baseFilters(), expandedAggIds: new Set([6]) });
      expect(out[0].children?.map((c) => c.id)).toEqual([7, 8]);
    });

    it("ships the aggregate childless when it is not expanded", () => {
      const sample = [node({ id: 7, pid: 7, path: "/usr/bin/s1" })];
      const out = buildVisibleRoots(aggRoots(sample), baseFilters());
      expect(out[0].children).toBeUndefined();
    });

    it("yields an empty child list for an expanded aggregate with no sample", () => {
      const out = buildVisibleRoots(aggRoots(undefined), { ...baseFilters(), expandedAggIds: new Set([6]) });
      expect(out[0].children).toEqual([]);
    });
  });
});

describe("resolveAlertEntry", () => {
  const alert: AlertDetail = {
    id: 842,
    host_id: "h1",
    rule_id: "suspicious_exec",
    source: "detection",
    severity: "high",
    title: "Suspicious exec chain",
    description: "d",
    techniques: [],
    process_id: 7,
    status: "open",
    created_at: "2026-06-18T12:00:00Z",
    updated_at: "2026-06-18T12:00:00Z",
    event_ids: ["evt-1"],
  };

  it("sources the anchor from the entryAlert prop (the /alerts/:alertId route)", () => {
    const entry = resolveAlertEntry(alert, new URLSearchParams());
    expect(entry.focus).toBe(true);
    expect(entry.processId).toBe(7);
    expect(entry.atMs).toBe(new Date("2026-06-18T12:00:00Z").getTime());
  });

  it("falls back to the ?alert=&process=&at= query on the host route", () => {
    const entry = resolveAlertEntry(undefined, new URLSearchParams("alert=842&process=7&at=1750248000000"));
    expect(entry.focus).toBe(true);
    expect(entry.processId).toBe(7);
    expect(entry.atMs).toBe(1750248000000);
  });

  it("reports no alert entry and zeroed anchor when neither prop nor query is present", () => {
    const entry = resolveAlertEntry(undefined, new URLSearchParams());
    expect(entry.focus).toBe(false);
    expect(entry.processId).toBe(0);
    expect(entry.atMs).toBe(0);
  });

  it("treats a process-optional alert (process_id 0) as processId 0", () => {
    expect(resolveAlertEntry({ ...alert, process_id: 0 }, new URLSearchParams()).processId).toBe(0);
  });
});
