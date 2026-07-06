// Pure helpers for ProcessTree.tsx (issue: consolidation cognitive-complexity paydown). Everything here is a side-effect-free data
// transform over the ProcessNode forest, the search query, or the d3 hierarchy: no React, no d3 DOM mutation. Extracted so the
// ProcessTree component and its d3 render effect stay under Sonar's cognitive-complexity cap. Behavior is identical to the inlined
// originals; these are verbatim moves plus three build* functions lifted out of the component's useMemo bodies unchanged.
import type { HierarchyPointNode } from "d3";
import type { ProcessNode } from "../types";
import { NANOSECONDS_PER_MILLISECOND } from "../constants";

export interface D3Node {
  name: string;
  pid: number;
  path: string;
  data: ProcessNode;
  children?: D3Node[];
}

export type D3PointNode = HierarchyPointNode<D3Node>;

// Path segments we treat as "system noise" for the hide-system toggle. We match on substring
// rather than prefix so that cryptex-mounted paths also match. On modern macOS a single framework
// binary can appear at any of, e.g.:
//   /System/Library/Frameworks/WebKit.framework/...
//   /System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/...
//   /System/Cryptexes/Incoming/OS/System/Library/Frameworks/WebKit.framework/...
// We deliberately do NOT filter /System/Applications/ (Safari, Mail, Notes, Messages, Calendar,
// etc.) because those are user-facing apps and are as valid an attack surface as anything in
// /Applications/. Anything packaged as a .app bundle is kept regardless of where it lives, so
// Finder, Dock, loginwindow-hosted apps, and the like also remain in the tree.
const SYSTEM_PATH_SEGMENTS = ["/System/Library/", "/usr/libexec/", "/Library/Apple/"];

function basename(path: string): string {
  if (!path) return "";
  const parts = path.split("/");
  return parts[parts.length - 1];
}

export function isSystemPath(path: string): boolean {
  // Any .app bundle is a user-launchable application, so keep it visible even if it lives
  // under /System/Library/ (e.g. /System/Library/CoreServices/Finder.app/...).
  if (path.includes(".app/")) return false;
  for (const seg of SYSTEM_PATH_SEGMENTS) {
    if (path.includes(seg)) return true;
  }
  return false;
}

export function countDescendants(node: ProcessNode): number {
  if (!node.children) return 0;
  let n = 0;
  for (const c of node.children) n += 1 + countDescendants(c);
  return n;
}

export function toD3Hierarchy(nodes: ProcessNode[]): D3Node {
  function convert(n: ProcessNode): D3Node {
    const kids = n.children?.map(convert);
    return {
      name: basename(n.path) || `PID ${String(n.pid)}`,
      pid: n.pid,
      path: n.path,
      data: n,
      children: kids && kids.length > 0 ? kids : undefined,
    };
  }

  if (nodes.length === 1) {
    return convert(nodes[0]);
  }

  return {
    name: "root",
    pid: 0,
    path: "",
    data: nodes[0],
    children: nodes.map(convert),
  };
}

// matchFields holds the four node fields the search box compares against.
// Both the d3-layout-time matcher and the data-side pre-filter funnel into
// this so the matching rules can't drift between them.
function matchFields(name: string, path: string, pid: number, args: string[] | undefined, q: string): boolean {
  if (name.toLowerCase().includes(q)) return true;
  if (path.toLowerCase().includes(q)) return true;
  if (String(pid).includes(q)) return true;
  if (args?.some((a) => a.toLowerCase().includes(q))) return true;
  return false;
}

function nodeMatchesQuery(d: D3Node, q: string): boolean {
  return matchFields(d.name, d.path, d.pid, d.data.args, q);
}

// matchesQueryRaw is the data-side mirror of nodeMatchesQuery: it operates on
// raw ProcessNode rows before the d3 layout runs. Used by the visible-tree
// pre-filter so the canvas only ever lays out the matches-plus-ancestors set.
function matchesQueryRaw(n: ProcessNode, q: string): boolean {
  const name = n.path.split("/").pop() ?? "";
  return matchFields(name, n.path, n.pid, n.args, q);
}

// collectMatches walks the laid-out nodes and returns every node whose payload matches
// q (by name/path/pid/args) plus the set of nodes on the ancestor path of any match,
// used to dim non-matching subtrees while keeping the context to the match visible.
export function collectMatches(
  nodes: D3PointNode[],
  q: string,
): { matches: D3PointNode[]; pathNodes: Set<D3PointNode> } {
  const matches: D3PointNode[] = [];
  const pathNodes = new Set<D3PointNode>();
  if (!q) return { matches, pathNodes };
  for (const n of nodes) {
    if (n.data.pid === 0) continue; // synthetic root when tree has multiple real roots
    if (!nodeMatchesQuery(n.data, q)) continue;
    matches.push(n);
    let cur: D3PointNode | null = n;
    while (cur) {
      pathNodes.add(cur);
      cur = cur.parent;
    }
  }
  return { matches, pathNodes };
}

// Given a root list and a target process row id, return the set of ids that form the alert
// chain: the target, every ancestor back to the top root, and every descendant. If the
// target isn't in the tree, returns an empty set (the focus filter will then drop the whole
// tree, making it visually obvious that the target is out of range).
export function findAlertChain(roots: ProcessNode[], targetDbId: number): Set<number> {
  const related = new Set<number>();
  let path: ProcessNode[] = [];
  const findPath = (nodes: ProcessNode[], acc: ProcessNode[]): boolean => {
    for (const n of nodes) {
      const next = [...acc, n];
      if (n.id === targetDbId) { path = next; return true; }
      if (n.children?.length && findPath(n.children, next)) return true;
    }
    return false;
  };
  findPath(roots, []);
  if (path.length === 0) return related;
  for (const p of path) related.add(p.id);
  const addDescendants = (n: ProcessNode) => {
    related.add(n.id);
    if (n.children) for (const c of n.children) addDescendants(c);
  };
  addDescendants(path[path.length - 1]);
  return related;
}

function findNodeByDbId(nodes: ProcessNode[], dbId: number): ProcessNode | null {
  for (const n of nodes) {
    if (n.id === dbId) return n;
    if (n.children) {
      const found = findNodeByDbId(n.children, dbId);
      if (found) return found;
    }
  }
  return null;
}

// findNodeByPidAtTime resolves a timeline row's (pid, event time) to its process node: the node with that pid whose lifetime brackets
// atNs (fork <= atNs, and no exit or exit >= atNs). This disambiguates pid reuse within the window by picking the generation live at
// the event, the same (host, pid, at) correlation the process-detail network join relies on. Prefers the closest fork at/before the
// anchor so an exact hit wins over a wider-lived ancestor sharing the pid.
function findNodeByPidAtTime(nodes: ProcessNode[], pid: number, atNs: number): ProcessNode | null {
  let best: ProcessNode | null = null;
  const visit = (n: ProcessNode) => {
    // !n.exit_time_ns covers a still-running process whether the API sends the field as undefined, null, or 0; a bare === undefined
    // check would treat a null (common for running processes over the Go/JSON boundary) as "exited at null" and drop the node.
    if (n.pid === pid && n.fork_time_ns <= atNs && (!n.exit_time_ns || n.exit_time_ns >= atNs)) {
      if (best === null || n.fork_time_ns > best.fork_time_ns) best = n;
    }
    for (const c of n.children ?? []) visit(c);
  };
  for (const n of nodes) visit(n);
  return best;
}

// selectNodeFromParams resolves the node the URL asks the graph to select: ?process=<dbId> directly, or ?pid=<pid>&at=<ms> (a timeline
// row) via findNodeByPidAtTime. Kept at module scope so the selection effect in ProcessTreeView stays a single branch.
// overrideProcessId, when set, selects that process DB id directly (the /alerts/:alertId route carries the alerted process on the
// entryAlert prop rather than in the URL); it takes precedence over the ?process= param. A 0 id (a process-optional alert) selects
// nothing.
export function selectNodeFromParams(roots: ProcessNode[], searchParams: URLSearchParams, overrideProcessId?: number): ProcessNode | null {
  if (roots.length === 0) return null;
  if (overrideProcessId) return findNodeByDbId(roots, overrideProcessId);
  const processIdParam = searchParams.get("process");
  if (processIdParam) return findNodeByDbId(roots, Number(processIdParam));
  const pidQuery = searchParams.get("pid");
  const atQuery = searchParams.get("at");
  if (pidQuery && atQuery) {
    return findNodeByPidAtTime(roots, Number(pidQuery), Number(atQuery) * NANOSECONDS_PER_MILLISECOND);
  }
  return null;
}

// viewHref toggles the view param on the current path while preserving the rest of the URL (window, alert anchor, selection), so
// switching views is a link that never changes the shared time window. basePath is the full pathname (e.g. /hosts/h1 or /alerts/842)
// so the toggle stays on whichever route rendered the view. Graph is the default, so it drops ?view= rather than setting view=graph.
export function viewHref(basePath: string, searchParams: URLSearchParams, v: "graph" | "timeline"): string {
  const next = new URLSearchParams(searchParams);
  if (v === "graph") {
    next.delete("view");
  } else {
    next.set("view", v);
  }
  const qs = next.toString();
  const suffix = qs ? `?${qs}` : "";
  return `${basePath}${suffix}`;
}

// buildPreservedIds: never hide processes that have alerts attached, or that sit on the ancestor path of one (even if their binary is
// in a system path, the analyst context matters). Lifted verbatim from ProcessTreeView's preservedIds useMemo (complexity paydown).
export function buildPreservedIds(roots: ProcessNode[], alertProcessIds: Set<number>): Set<number> {
  const keep = new Set<number>();
  const walk = (node: ProcessNode, ancestors: number[]) => {
    const nextAncestors = [...ancestors, node.id];
    if (alertProcessIds.has(node.id)) {
      for (const id of nextAncestors) keep.add(id);
    }
    if (node.children) for (const c of node.children) walk(c, nextAncestors);
  };
  for (const r of roots) walk(r, []);
  return keep;
}

// buildQueryFilterIds: the set of ids to keep visible while a search query is active (every matching node plus its ancestors), so the
// canvas only ever lays out the matches-plus-ancestors set instead of dimming a wall of noise. Null when the query is empty. Lifted
// verbatim from ProcessTreeView's queryFilterIds useMemo.
export function buildQueryFilterIds(roots: ProcessNode[], query: string): Set<number> | null {
  const q = query.trim().toLowerCase();
  if (!q) return null;
  const keep = new Set<number>();
  const visit = (nodes: ProcessNode[], ancestors: number[]): boolean => {
    let anyMatch = false;
    for (const n of nodes) {
      const matches = matchesQueryRaw(n, q);
      const childMatches = n.children ? visit(n.children, [...ancestors, n.id]) : false;
      if (matches || childMatches) {
        keep.add(n.id);
        for (const a of ancestors) keep.add(a);
        anyMatch = true;
      }
    }
    return anyMatch;
  };
  visit(roots, []);
  return keep;
}

// VisibilityFilters bundles the derived state buildVisibleRoots reshapes the raw forest against; grouped so the call stays one argument.
export interface VisibilityFilters {
  showSystem: boolean;
  collapsedIds: Set<number>;
  expandedAggIds: Set<number>;
  preservedIds: Set<number>;
  applyCollapse: boolean;
  alertChainIds: Set<number> | null;
  queryFilterIds: Set<number> | null;
}

// buildVisibleRoots re-shapes the raw tree according to the current filters: hide system-path nodes unconditionally (except preserved),
// optionally restrict to the alert chain, and drop children of collapsed nodes while stashing the hidden-count on the surviving parent
// so it can render as "+N". While a search query is active the collapse step is skipped (applyCollapse false) so a match hidden inside a
// collapsed subtree still surfaces, and the tree is pruned to matches + ancestors. Lifted verbatim from ProcessTreeView's visibleRoots
// useMemo (issue: complexity paydown).
export function buildVisibleRoots(roots: ProcessNode[], filters: VisibilityFilters): ProcessNode[] {
  const { showSystem, collapsedIds, expandedAggIds, preservedIds, applyCollapse, alertChainIds, queryFilterIds } = filters;
  // Predicate for "is this node visible at all": pulled out to keep the
  // recursive walk below under Sonar's cognitive-complexity cap.
  const isVisible = (n: ProcessNode): boolean => {
    if (alertChainIds && !alertChainIds.has(n.id)) return false;
    if (!showSystem && isSystemPath(n.path) && !preservedIds.has(n.id)) return false;
    // Search filter: hide everything outside the matches-plus-ancestors set so
    // a query like "60289" reduces a 200-node tree to the few rows that matter,
    // instead of dimming 195 nodes the user has to visually skip past.
    if (queryFilterIds && !queryFilterIds.has(n.id)) return false;
    return true;
  };
  const apply = (nodes: ProcessNode[]): ProcessNode[] => {
    const out: ProcessNode[] = [];
    for (const n of nodes) {
      if (!isVisible(n)) continue;
      // An aggregated "×N" node ships childless; when the analyst expands it, its capped sample becomes its children in place
      // (issue #416). Its own subtree is always the sample, so the generic collapse machinery below doesn't apply to it.
      if (n.aggregated) {
        const sample = expandedAggIds.has(n.id) ? apply(n.aggregated.sample ?? []) : undefined;
        out.push({ ...n, children: sample });
        continue;
      }
      const kids = n.children ? apply(n.children) : undefined;
      if (applyCollapse && collapsedIds.has(n.id) && kids && kids.length > 0) {
        const collapsedTotal = kids.reduce((acc, c) => acc + 1 + countDescendants(c), 0);
        out.push({ ...n, children: undefined, _collapsedCount: collapsedTotal });
      } else {
        out.push({ ...n, children: kids });
      }
    }
    return out;
  };
  return apply(roots);
}
