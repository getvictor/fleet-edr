import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { useParams, useSearchParams, Link } from "react-router-dom";
import * as d3 from "d3";
import { getAlertDetail, getProcessTree, listAlerts } from "../api";
import type { AlertDetail, ProcessNode } from "../types";
import { ProcessDetail } from "./ProcessDetail";
import { Badge, type BadgeVariant } from "./ui/Badge";
import { Button } from "./ui/Button";
import { PageHeader } from "./ui/PageHeader";
import "./ProcessTree.scss";

const SEVERITY_VARIANTS: Record<string, BadgeVariant> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

const TIME_RANGES: { label: string; ms: number }[] = [
  { label: "15 min", ms: 15 * 60 * 1000 },
  { label: "1 hour", ms: 60 * 60 * 1000 },
  { label: "6 hours", ms: 6 * 60 * 60 * 1000 },
  { label: "24 hours", ms: 24 * 60 * 60 * 1000 },
];

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

const SHOW_SYSTEM_STORAGE_KEY = "edr.processTree.showSystem";

type D3PointNode = d3.HierarchyPointNode<D3Node>;

interface RenderResult {
  zoom: d3.ZoomBehavior<SVGSVGElement, unknown>;
  nodes: D3PointNode[];
}

export function ProcessTreeView() {
  const { hostId } = useParams<{ hostId: string }>();
  const [searchParams] = useSearchParams();
  const svgRef = useRef<SVGSVGElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const layoutNodesRef = useRef<D3PointNode[]>([]);
  const matchesRef = useRef<D3PointNode[]>([]);
  const [roots, setRoots] = useState<ProcessNode[]>([]);
  const [selectedNode, setSelectedNode] = useState<ProcessNode | null>(null);
  // Default to 24h window when navigating from an alert (alert times may be days old);
  // otherwise default to 1h for the live view.
  const [rangeIdx, setRangeIdx] = useState(() => (searchParams.get("at") ? 3 : 1));
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [alertProcessIds, setAlertProcessIds] = useState<Set<number>>(new Set());
  const [query, setQuery] = useState("");
  const [matchIdx, setMatchIdx] = useState(0);
  const [matchCount, setMatchCount] = useState(0);
  // System processes (framework daemons, libexec helpers, etc.) are hidden by default.
  // Flipping the toggle on reveals them. Persisted across reloads.
  const [showSystem, setShowSystem] = useState<boolean>(() => {
    try {
      const stored = localStorage.getItem(SHOW_SYSTEM_STORAGE_KEY);
      return stored === "true";
    } catch {
      return false;
    }
  });
  const [collapsedIds, setCollapsedIds] = useState<Set<number>>(new Set());
  // Alert focus mode: when we arrived from an alert link, the tree defaults to showing only
  // the alerted process plus its ancestors and descendants — "related processes only" — so
  // the analyst isn't wading through a forest of unrelated background daemons. Toggleable.
  const [focusAlertChain, setFocusAlertChain] = useState<boolean>(
    () => searchParams.get("alert") !== null,
  );
  const [alertDetail, setAlertDetail] = useState<AlertDetail | null>(null);

  useEffect(() => {
    try { localStorage.setItem(SHOW_SYSTEM_STORAGE_KEY, String(showSystem)); } catch { /* ignore */ }
  }, [showSystem]);

  // Fetch the alert so we can render a breadcrumb with title/severity/timestamp.
  useEffect(() => {
    const alertIdParam = searchParams.get("alert");
    if (!alertIdParam) {
      setAlertDetail(null); // eslint-disable-line react-hooks/set-state-in-effect -- clear on param removal
      return;
    }
    const alertId = Number(alertIdParam);
    let cancelled = false;
    getAlertDetail(alertId)
      .then((result) => { if (!cancelled) setAlertDetail(result); })
      .catch(() => { if (!cancelled) setAlertDetail(null); });
    return () => { cancelled = true; };
  }, [searchParams]);

  // Compute the set of process row-ids that make up the alert chain:
  // the alerted process, every ancestor back to the root, and every descendant.
  // Used by the focus-mode filter to drop everything unrelated to the alert.
  const alertChainIds = useMemo(() => {
    const processIdParam = searchParams.get("process");
    if (!focusAlertChain || !processIdParam) return null;
    const targetId = Number(processIdParam);
    return findAlertChain(roots, targetId);
  }, [roots, searchParams, focusAlertChain]);

  // Never hide processes that have alerts attached, or that sit on the ancestor path of one —
  // even if their binary is in a system path, the analyst context matters.
  const preservedIds = useMemo(() => {
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
  }, [roots, alertProcessIds]);

  // Re-shape the raw tree according to the current filters: hide system-path nodes
  // unconditionally (except preserved), optionally restrict to the alert chain, and drop
  // children of collapsed nodes while stashing the hidden-count on the surviving parent so
  // we can render it as "+N". While a search query is active, skip the collapse step so the
  // user never sees "0 matches" when a match is only hidden inside a collapsed subtree.
  const applyCollapse = query.trim() === "";
  const visibleRoots = useMemo(() => {
    const apply = (nodes: ProcessNode[]): ProcessNode[] => {
      const out: ProcessNode[] = [];
      for (const n of nodes) {
        // In alert focus mode, drop anything that isn't on the alert's ancestor/descendant chain.
        if (alertChainIds && !alertChainIds.has(n.id)) continue;
        if (!showSystem && isSystemPath(n.path) && !preservedIds.has(n.id)) continue;
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
  }, [roots, showSystem, collapsedIds, preservedIds, applyCollapse, alertChainIds]);

  const toggleCollapsed = useCallback((nodeId: number) => {
    setCollapsedIds((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) next.delete(nodeId); else next.add(nodeId);
      return next;
    });
  }, []);

  const fetchTree = useCallback(() => {
    if (!hostId) return;
    setLoading(true);
    setError(null);

    // Anchor the window on the alert time when arriving from the alert list; fall back to now.
    const atParam = searchParams.get("at");
    const anchorMs = atParam ? Number(atParam) : Date.now();
    const to = anchorMs * 1_000_000;
    const range = TIME_RANGES[rangeIdx];
    const from = to - range.ms * 1_000_000;

    getProcessTree(hostId, from, to)
      .then((res) => { setRoots(res.roots); })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Unknown error");
      })
      .finally(() => { setLoading(false); });
  }, [hostId, rangeIdx, searchParams]);

  // Fetch alerts for this host to mark nodes with alert badges.
  useEffect(() => {
    if (!hostId) return;
    let cancelled = false;
    listAlerts({ host_id: hostId, status: "open", limit: 1000 })
      .then((alerts) => {
        if (cancelled) return;
        const ids = new Set(alerts.map((a) => a.process_id));
        // Also include acknowledged alerts.
        return listAlerts({ host_id: hostId, status: "acknowledged", limit: 1000 }).then((acked) => {
          if (cancelled) return;
          for (const a of acked) ids.add(a.process_id);
          setAlertProcessIds(ids);
        });
      })
      .catch(() => { /* alert badges are best-effort */ });
    return () => { cancelled = true; };
  }, [hostId]);

  // Auto-select process from URL query params (from alert list navigation).
  useEffect(() => {
    const processIdParam = searchParams.get("process");
    if (processIdParam && roots.length > 0) {
      const processId = Number(processIdParam);
      const found = findNodeByDbId(roots, processId);
      if (found) setSelectedNode(found); // eslint-disable-line react-hooks/set-state-in-effect -- auto-select from URL
    }
  }, [roots, searchParams]);

  useEffect(() => {
    fetchTree(); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch on mount
  }, [fetchTree]);

  useEffect(() => {
    if (!svgRef.current) return;
    if (visibleRoots.length === 0) {
      d3.select(svgRef.current).selectAll("*").remove();
      layoutNodesRef.current = [];
      return;
    }
    const result = renderTree(svgRef.current, visibleRoots, setSelectedNode, alertProcessIds, collapsedIds, toggleCollapsed);
    layoutNodesRef.current = result.nodes;
  }, [visibleRoots, alertProcessIds, collapsedIds, toggleCollapsed]);

  // Focus the currently-active match: scroll the canvas so the match sits near the
  // vertical centre, preserving the user's current zoom level and scroll position
  // horizontally where possible.
  const zoomToNode = useCallback((node: D3PointNode) => {
    const svg = svgRef.current;
    const canvas = svg?.parentElement;
    if (!svg || !canvas) return;
    const tr = d3.zoomTransform(svg);
    // Node's y in the hierarchy layout is its vertical position; x-axis of the hierarchy
    // is horizontal because we invert the layout in linkHorizontal. After the current zoom
    // transform, the node's on-screen y is node.x * k + tr.y, and its on-screen x is
    // node.y * k + tr.x.
    const nodeScreenY = node.x * tr.k + tr.y;
    const nodeScreenX = node.y * tr.k + tr.x;
    const targetTop = Math.max(0, nodeScreenY - canvas.clientHeight / 2);
    // Only adjust horizontal scroll when the match is outside the current viewport;
    // preserve the user's horizontal position otherwise so deep-tree panning feels stable.
    const curLeft = canvas.scrollLeft;
    const inHorizontalView = nodeScreenX >= curLeft + 40
      && nodeScreenX <= curLeft + canvas.clientWidth - 40;
    const targetLeft = inHorizontalView ? curLeft : Math.max(0, nodeScreenX - canvas.clientWidth / 2);
    canvas.scrollTo({ top: targetTop, left: targetLeft, behavior: "smooth" });
  }, []);

  // Re-run highlighting whenever the query or the rendered tree changes.
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    const q = query.toLowerCase().trim();

    // Compute matches and the set of nodes on the ancestor path of any match.
    const matches: D3PointNode[] = [];
    const pathNodes = new Set<D3PointNode>();
    if (q) {
      for (const n of layoutNodesRef.current) {
        const d = n.data;
        if (d.pid === 0) continue; // synthetic root when tree has multiple real roots
        if (nodeMatchesQuery(d, q)) {
          matches.push(n);
          let cur: D3PointNode | null = n;
          while (cur) {
            pathNodes.add(cur);
            cur = cur.parent;
          }
        }
      }
    }
    matchesRef.current = matches;
    /* eslint-disable react-hooks/set-state-in-effect -- derived from DOM walk after tree render */
    setMatchCount(matches.length);
    if (matches.length === 0) {
      setMatchIdx(0);
    } else {
      setMatchIdx((prev) => (prev < matches.length ? prev : 0));
    }
    /* eslint-enable react-hooks/set-state-in-effect */

    svg.selectAll<SVGGElement, D3PointNode>("g.node")
      .classed("node--match", (d) => matches.includes(d))
      .classed("node--path", (d) => !matches.includes(d) && pathNodes.has(d))
      .classed("node--dim", (d) => q !== "" && !pathNodes.has(d));

    svg.selectAll<SVGPathElement, d3.HierarchyLink<D3Node>>("path.link")
      .classed(
        "link--path",
        (d) => pathNodes.has(d.source as D3PointNode) && pathNodes.has(d.target as D3PointNode),
      )
      .classed(
        "link--dim",
        (d) => q !== ""
          && !(pathNodes.has(d.source as D3PointNode) && pathNodes.has(d.target as D3PointNode)),
      );

    if (matches.length > 0) zoomToNode(matches[0]);
  }, [query, visibleRoots, alertProcessIds, zoomToNode]);

  // Global "/" keyboard shortcut to focus the search box.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key !== "/") return;
      const target = e.target as HTMLElement | null;
      // Don't steal focus if the user is already typing in an input/textarea.
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA")) return;
      e.preventDefault();
      searchInputRef.current?.focus();
      searchInputRef.current?.select();
    };
    window.addEventListener("keydown", handler);
    return () => { window.removeEventListener("keydown", handler); };
  }, []);

  const stepMatch = useCallback((delta: number) => {
    const total = matchesRef.current.length;
    if (total === 0) return;
    setMatchIdx((prev) => {
      const next = (prev + delta + total) % total;
      zoomToNode(matchesRef.current[next]);
      return next;
    });
  }, [zoomToNode]);

  if (!hostId) return <p>No host selected.</p>;

  const headerActions = (
    <div className="process-tree__controls">
      <div className="process-tree__search">
        <input
          ref={searchInputRef}
          type="search"
          className="process-tree__search-input"
          placeholder="Search name, path, pid (press /)"
          value={query}
          onChange={(e) => { setQuery(e.target.value); }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              stepMatch(e.shiftKey ? -1 : 1);
            } else if (e.key === "Escape") {
              setQuery("");
            }
          }}
        />
        {query && (
          <span className="process-tree__search-count">
            {matchCount === 0 ? "0 matches" : `${String(matchIdx + 1)} / ${String(matchCount)}`}
          </span>
        )}
      </div>
      <div className="process-tree__range" role="group" aria-label="Time range">
        {TIME_RANGES.map((r, i) => (
          <button
            key={r.label}
            type="button"
            className={`process-tree__range-item${i === rangeIdx ? " process-tree__range-item--active" : ""}`}
            onClick={() => { setRangeIdx(i); }}
          >
            {r.label}
          </button>
        ))}
      </div>
      <label
        className="process-tree__toggle"
        title={showSystem ? "System processes shown" : "System processes hidden"}
      >
        <input
          type="checkbox"
          className="process-tree__toggle-input"
          checked={showSystem}
          onChange={(e) => { setShowSystem(e.target.checked); }}
        />
        <span className="process-tree__toggle-switch" aria-hidden="true" />
        <span className="process-tree__toggle-label">Show system</span>
      </label>
      <button type="button" className="process-tree__action-btn" onClick={fetchTree}>
        Refresh
      </button>
    </div>
  );

  return (
    <>
      <PageHeader
        title={
          <span className="process-tree__title">
            <Link to="/" className="process-tree__back">&larr; Hosts</Link>
            <span className="process-tree__host">{hostId}</span>
          </span>
        }
        actions={headerActions}
      />

      {alertDetail && (
        <div className="alert-breadcrumb">
          <Link to="/alerts" className="alert-breadcrumb__back">&larr; Alerts</Link>
          <span className="alert-breadcrumb__sep">/</span>
          <span className="alert-breadcrumb__id">#{String(alertDetail.id)}</span>
          <Badge variant={SEVERITY_VARIANTS[alertDetail.severity] ?? "neutral"}>
            {alertDetail.severity}
          </Badge>
          <span className="alert-breadcrumb__title">{alertDetail.title}</span>
          <span className="alert-breadcrumb__time">
            {new Date(alertDetail.created_at).toLocaleString()}
          </span>
          <span className="alert-breadcrumb__spacer" />
          <Button
            size="small"
            variant={focusAlertChain ? "primary" : "inverse"}
            onClick={() => { setFocusAlertChain((v) => !v); }}
            title={focusAlertChain
              ? "Showing only the alert's process chain"
              : "Showing the full host tree"}
          >
            {focusAlertChain ? "Focused on chain" : "Show full tree"}
          </Button>
        </div>
      )}

      {loading && <p className="process-tree__status">Loading...</p>}
      {error && <p className="process-tree__status process-tree__status--error">Error: {error}</p>}
      {!loading && roots.length === 0 && (
        <p className="process-tree__status">No processes in this time range.</p>
      )}

      <div className="process-tree__layout">
        <div className="process-tree__canvas">
          <svg ref={svgRef} />
        </div>
        {selectedNode && (
          <aside className="process-tree__detail">
            <ProcessDetail
              hostId={hostId}
              node={selectedNode}
              onClose={() => { setSelectedNode(null); }}
            />
          </aside>
        )}
      </div>
    </>
  );
}

function nodeMatchesQuery(d: D3Node, q: string): boolean {
  if (d.name.toLowerCase().includes(q)) return true;
  if (d.path.toLowerCase().includes(q)) return true;
  if (String(d.pid).includes(q)) return true;
  const args = d.data.args;
  if (args && args.some((a) => a.toLowerCase().includes(q))) return true;
  return false;
}

function isSystemPath(path: string): boolean {
  // Any .app bundle is a user-launchable application — keep it visible even if it lives
  // under /System/Library/ (e.g. /System/Library/CoreServices/Finder.app/...).
  if (path.includes(".app/")) return false;
  for (const seg of SYSTEM_PATH_SEGMENTS) {
    if (path.includes(seg)) return true;
  }
  return false;
}

function countDescendants(node: ProcessNode): number {
  if (!node.children) return 0;
  let n = 0;
  for (const c of node.children) n += 1 + countDescendants(c);
  return n;
}

// Given a root list and a target process row id, return the set of ids that form the alert
// chain — the target, every ancestor back to the top root, and every descendant. If the
// target isn't in the tree, returns an empty set (the focus filter will then drop the whole
// tree, making it visually obvious that the target is out of range).
function findAlertChain(roots: ProcessNode[], targetDbId: number): Set<number> {
  const related = new Set<number>();
  let path: ProcessNode[] = [];
  const findPath = (nodes: ProcessNode[], acc: ProcessNode[]): boolean => {
    for (const n of nodes) {
      const next = [...acc, n];
      if (n.id === targetDbId) { path = next; return true; }
      if (n.children && findPath(n.children, next)) return true;
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

interface D3Node {
  name: string;
  pid: number;
  path: string;
  data: ProcessNode;
  children?: D3Node[];
}

function toD3Hierarchy(nodes: ProcessNode[]): D3Node {
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

function basename(path: string): string {
  if (!path) return "";
  const parts = path.split("/");
  return parts[parts.length - 1];
}

function renderTree(
  svg: SVGSVGElement,
  roots: ProcessNode[],
  onSelect: (node: ProcessNode) => void,
  alertProcessIds: Set<number> = new Set(),
  collapsedIds: Set<number> = new Set(),
  onToggleCollapsed?: (nodeId: number) => void,
): RenderResult {
  const nodeHeight = 28;

  const hierarchy = toD3Hierarchy(roots);
  const root = d3.hierarchy(hierarchy);

  const treeLayout = d3.tree<D3Node>().nodeSize([nodeHeight, 220]);
  treeLayout(root);

  const nodes = root.descendants() as D3PointNode[];
  const links = root.links();

  // Compute bounding box.
  let minY = Infinity, maxY = -Infinity;
  let minX = Infinity, maxX = -Infinity;
  for (const n of nodes) {
    if (n.x < minX) minX = n.x;
    if (n.x > maxX) maxX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.y > maxY) maxY = n.y;
  }

  const margin = 40;
  const svgHeight = maxX - minX + margin * 2;

  const sel = d3.select(svg);
  sel.selectAll("*").remove();
  sel.attr("height", svgHeight);

  const g = sel
    .append("g")
    .attr("transform", `translate(${String(margin - minY)},${String(margin - minX)})`);

  // Zoom behavior.
  const zoom = d3.zoom<SVGSVGElement, unknown>().scaleExtent([0.2, 3]).on("zoom", (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
    g.attr("transform", String(event.transform));
  });
  sel.call(zoom);
  // eslint-disable-next-line @typescript-eslint/unbound-method
  sel.call(zoom.transform, d3.zoomIdentity.translate(margin - minY, margin - minX));

  // Links.
  g.selectAll("path.link")
    .data(links)
    .join("path")
    .attr("class", "link")
    .attr("fill", "none")
    .attr(
      "d",
      d3
        .linkHorizontal<d3.HierarchyLink<D3Node>, d3.HierarchyPointNode<D3Node>>()
        .x((d) => d.y)
        .y((d) => d.x) as never
    );

  // Nodes.
  const node = g
    .selectAll("g.node")
    .data(nodes.filter((n) => n.data.pid !== 0 || roots.length === 1))
    .join("g")
    .attr("class", "node")
    .attr("transform", (d) => `translate(${String(d.y)},${String(d.x)})`)
    .style("cursor", "pointer")
    .on("click", (_, d) => {
      onSelect(d.data.data);
    });

  node
    .append("circle")
    .attr("class", "node__dot")
    .attr("r", 5)
    .attr("fill", (d) => {
      // Fleet UI colors: ui-fleet-black-50 for exited, core-fleet-green for live.
      if (d.data.data.exit_time_ns) return "#8b8fa2";
      return "#009a7d";
    });

  // Alert badge: vibrant red ring around nodes with open/acknowledged alerts.
  node
    .filter((d) => alertProcessIds.has(d.data.data.id))
    .append("circle")
    .attr("class", "node__alert-ring")
    .attr("r", 9)
    .attr("fill", "none")
    .attr("stroke", "#ff5c83")
    .attr("stroke-width", 2);

  // Collapse/expand chevron. Sits in front of the dot. Only rendered when a node has
  // children in the underlying data OR has been collapsed (so we can expand it back).
  // Click events on the chevron stop propagation so they don't also fire the node-select handler.
  const chevronNodes = node.filter((d) => {
    const p = d.data.data;
    return (p.children !== undefined && p.children.length > 0) || collapsedIds.has(p.id);
  });
  chevronNodes
    .append("text")
    .attr("class", "node__chevron")
    .attr("dx", -14)
    .attr("dy", 4)
    .attr("font-size", "10px")
    .attr("font-family", "ui-monospace, SFMono-Regular, Menlo, monospace")
    .attr("fill", "#515774")
    .style("cursor", "pointer")
    .text((d) => (collapsedIds.has(d.data.data.id) ? "▶" : "▼"))
    .on("click", (event: MouseEvent, d) => {
      event.stopPropagation();
      onToggleCollapsed?.(d.data.data.id);
    });

  node
    .append("text")
    .attr("class", "node__label")
    .attr("dx", 8)
    .attr("dy", 4)
    .attr("font-size", "12px")
    .attr("font-family", "ui-monospace, SFMono-Regular, Menlo, monospace")
    .attr("fill", "#192147") // core-fleet-black
    .text((d) => {
      const base = `${d.data.name} (${String(d.data.pid)})`;
      const hidden = d.data.data._collapsedCount;
      return hidden && hidden > 0 ? `${base}  +${String(hidden)}` : base;
    });

  return { zoom, nodes };
}
