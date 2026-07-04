import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { useParams, useSearchParams, Link } from "react-router-dom";
import * as d3 from "d3";
import { getAlertDetail, getProcessTree, listAlerts } from "../api";
import type { AlertDetail, ProcessNode } from "../types";
import {
  NANOSECONDS_PER_MILLISECOND,
} from "../constants";
import { ProcessDetail } from "./ProcessDetail";
import { HostHealthPanel } from "./HostHealthPanel";
import { HostHeader } from "./HostHeader";
import { HostTimeline } from "./HostTimeline";
import { buildNodeTooltip, nodeEvidenceMarked, type NodeTooltip } from "./node-tooltip";
import { TimeRangeControl } from "./TimeRangeControl";
import { ActivityHistogram } from "./ActivityHistogram";
import { DEFAULT_ALERT_WINDOW_MS, DEFAULT_LIVE_WINDOW_MS, windowBounds, type TimeWindow } from "../timewindow";
import { Badge, type BadgeVariant } from "./ui/Badge";
import { Button } from "./ui/Button";
import "./ProcessTree.scss";

const SEVERITY_VARIANTS: Record<string, BadgeVariant> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

// d3 layout + render constants. Tuned by hand; collected here so a future
// "make labels bigger" change touches one block instead of every selector.
const TREE_NODE_HEIGHT_PX = 28;
const TREE_NODE_WIDTH_PX = 220;
const TREE_MARGIN_PX = 40;
const TREE_ZOOM_MIN = 0.2;
const TREE_ZOOM_MAX = 3;
const NODE_DOT_RADIUS_DEFAULT = 5;
// Evidence tooltip layout (issue #580): how far the hover card sits from the pointer, and the room reserved so a card near the
// right/bottom viewport edge clamps back into view instead of rendering off-screen (width tracks the card's 34rem max-width).
const TOOLTIP_POINTER_OFFSET_PX = 14;
const TOOLTIP_CLAMP_WIDTH_PX = 560;
const TOOLTIP_CLAMP_HEIGHT_PX = 170;
const NODE_DOT_RADIUS_ALERTED = 8;
const CHEVRON_DX = -14;
const CHEVRON_DY = 4;
const LABEL_DX = 16;
const LABEL_DY = 4;
const LABEL_BG_PAD_X = 3;
const LABEL_BG_PAD_Y = 1;
const LABEL_BG_EXTRA_WIDTH = LABEL_BG_PAD_X * 2;
const LABEL_BG_EXTRA_HEIGHT = LABEL_BG_PAD_Y * 2;

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
const FLATTEN_STORAGE_KEY = "edr.processTree.flatten";

type D3PointNode = d3.HierarchyPointNode<D3Node>;

interface RenderResult {
  zoom: d3.ZoomBehavior<SVGSVGElement, unknown>;
  nodes: D3PointNode[];
}

// TreeInteractions bundles the node-state + callbacks renderTree needs so its signature stays under the parameter cap. alertProcessIds
// drives the alert dot; collapsedIds/onToggleCollapsed drive the generic subtree collapse; expandedAggIds/onToggleAggExpanded drive
// the issue-#416 aggregated-node expand.
interface TreeInteractions {
  alertProcessIds: Set<number>;
  collapsedIds: Set<number>;
  onToggleCollapsed?: (nodeId: number) => void;
  expandedAggIds: Set<number>;
  onToggleAggExpanded?: (nodeId: number) => void;
  // onHover reports pointer entry/exit over a node so the component can render the evidence tooltip (issue #580); null clears it.
  onHover?: (hover: { x: number; y: number; tooltip: NodeTooltip } | null) => void;
}

export function ProcessTreeView() {
  const { hostId } = useParams<{ hostId: string }>();
  const [searchParams] = useSearchParams();
  // The active host-page view (issue #583): the process graph (default) or the flat event timeline. Held in the URL so a switch is
  // bookmarkable and the shared time window / alert anchor survive it.
  const view: "graph" | "timeline" = searchParams.get("view") === "timeline" ? "timeline" : "graph";
  // The process of interest carried across the graph<->timeline pivots: in the graph it selects the node (with ?at=), in the timeline
  // it emphasizes that process's rows.
  const pidParam = searchParams.get("pid");
  const emphasizePid = pidParam ? Number(pidParam) : undefined;
  const svgRef = useRef<SVGSVGElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const layoutNodesRef = useRef<D3PointNode[]>([]);
  const matchesRef = useRef<D3PointNode[]>([]);
  const [roots, setRoots] = useState<ProcessNode[]>([]);
  const [selectedNode, setSelectedNode] = useState<ProcessNode | null>(null);
  // The page's single time source (issue #581). Arriving from an alert anchors a wide window at the alert time (the alert-pivot
  // requirement's default); otherwise a live 1h window. Every consumer (tree fetch, histogram, control label) reads windowBounds
  // of this one value; a relative window's "now" is the frozen nowMs below, re-captured only by the Refresh action.
  const [timeWindow, setTimeWindow] = useState<TimeWindow>(() => {
    const parsedAt = Number(searchParams.get("at"));
    return Number.isFinite(parsedAt) && parsedAt > 0
      ? { kind: "relative", ms: DEFAULT_ALERT_WINDOW_MS, anchorNs: parsedAt * NANOSECONDS_PER_MILLISECOND }
      : { kind: "relative", ms: DEFAULT_LIVE_WINDOW_MS };
  });
  // The alert anchor lives in the ?at= param. React Router keeps this component mounted when the param changes (e.g. the alert
  // breadcrumb's "back to host" link drops it), so re-derive the entry window whenever ?at= transitions rather than only on mount.
  const atParam = searchParams.get("at");
  const lastAtRef = useRef<string | null>(atParam);
  useEffect(() => {
    if (lastAtRef.current === atParam) return;
    lastAtRef.current = atParam;
    const parsedAt = Number(atParam);
     
    setTimeWindow(
      Number.isFinite(parsedAt) && parsedAt > 0
        ? { kind: "relative", ms: DEFAULT_ALERT_WINDOW_MS, anchorNs: parsedAt * NANOSECONDS_PER_MILLISECOND }
        : { kind: "relative", ms: DEFAULT_LIVE_WINDOW_MS },
    );
     
  }, [atParam]);

  // nowMs is the page's single frozen "now": captured once on mount and re-captured only on Refresh, never read live during render.
  // Every relative-window resolution (bounds here, the shift arrows, the absolute-picker draft) uses this one value, so a relative
  // window that has been on screen a while cannot resolve to a moving clock in one place and a stale one in another.
  const [nowMs, setNowMs] = useState(() => Date.now());
  // bounds is pure over (timeWindow, nowMs): both are state, so no clock read happens during render and there is no mount double-render.
  const bounds = useMemo(() => windowBounds(timeWindow, nowMs), [timeWindow, nowMs]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [alertProcessIds, setAlertProcessIds] = useState<Set<number>>(new Set());
  // hoverTip is the evidence tooltip's position + content (issue #580); null when no node is hovered.
  const [hoverTip, setHoverTip] = useState<{ x: number; y: number; tooltip: NodeTooltip } | null>(null);
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
  // Flatten opts out of server-side sibling aggregation (issue #416): when on, the tree fetch asks for the raw forest so an analyst
  // sees every repeated exec as its own node instead of a collapsed "×N". Persisted across reloads like showSystem.
  const [flatten, setFlatten] = useState<boolean>(() => {
    try {
      return localStorage.getItem(FLATTEN_STORAGE_KEY) === "true";
    } catch {
      return false;
    }
  });
  const [collapsedIds, setCollapsedIds] = useState<Set<number>>(new Set());
  // Aggregated "×N" nodes ship collapsed; expanding one materializes its capped sample as children in place (issue #416). Keyed by
  // the aggregated node's representative row id.
  const [expandedAggIds, setExpandedAggIds] = useState<Set<number>>(new Set());
  // Alert focus mode: when we arrived from an alert link, the tree defaults to showing only
  // the alerted process plus its ancestors and descendants (the "related processes only" view), so
  // the analyst isn't wading through a forest of unrelated background daemons. Toggleable.
  const [focusAlertChain, setFocusAlertChain] = useState<boolean>(
    () => searchParams.get("alert") !== null,
  );
  const [alertDetail, setAlertDetail] = useState<AlertDetail | null>(null);

  // A process-optional alert (process_id === 0) has no attributed process node to focus on: it keys on an artifact, not a
  // process (e.g. a LaunchDaemon registration, where the BTM instigator is Apple's smd, not the actor). Focus mode would
  // filter the forest to an empty chain and render a silent blank canvas, so these alerts get an explicit explanation +
  // opt-in expansion instead. We key on the ?process=0 URL param FIRST (it mirrors process_id and is available on the very
  // first render) so the explanation shows immediately: the focus filter already empties the forest from that same param on
  // mount, so deriving this from the async alertDetail alone would leave a blank canvas during the fetch (or permanently if
  // getAlertDetail fails) before the explanation appears. alertDetail.process_id is the fallback for any path that omits the
  // param.
  const isProcessOptionalAlert = searchParams.get("process") === "0" || (alertDetail !== null && alertDetail.process_id === 0);

  useEffect(() => {
    try { localStorage.setItem(SHOW_SYSTEM_STORAGE_KEY, String(showSystem)); } catch { /* ignore */ }
  }, [showSystem]);

  useEffect(() => {
    try { localStorage.setItem(FLATTEN_STORAGE_KEY, String(flatten)); } catch { /* ignore */ }
  }, [flatten]);

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

  // Never hide processes that have alerts attached, or that sit on the ancestor path of one -
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
  // user never sees "0 matches" when a match is only hidden inside a collapsed subtree
  // AND prune to just matches + ancestors so the canvas isn't a wall of dimmed noise.
  const applyCollapse = query.trim() === "";
  const queryFilterIds = useMemo(() => {
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
  }, [roots, query]);
  const visibleRoots = useMemo(() => {
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
  }, [roots, showSystem, collapsedIds, expandedAggIds, preservedIds, applyCollapse, alertChainIds, queryFilterIds]);

  const toggleCollapsed = useCallback((nodeId: number) => {
    setCollapsedIds((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) next.delete(nodeId); else next.add(nodeId);
      return next;
    });
  }, []);

  const toggleAggExpanded = useCallback((nodeId: number) => {
    setExpandedAggIds((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) next.delete(nodeId); else next.add(nodeId);
      return next;
    });
  }, []);

  const fetchTree = useCallback(() => {
    if (!hostId) return;
    setLoading(true);
    setError(null);

    // Stale-response guard: bounds changes can overlap (rapid preset picks, histogram clicks), and an older tree response landing
    // after a newer one would paint the wrong window. Ignore all but the latest in-flight request, mirroring the alert fetch.
    let cancelled = false;
    getProcessTree(hostId, bounds.fromNs, bounds.toNs, undefined, flatten)
      .then((res) => { if (!cancelled) setRoots(res.roots); })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Unknown error");
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [hostId, bounds, flatten]);

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

  // Auto-select a process from URL query params: ?process=<dbId> from the alert list / fleet search, or ?pid=<pid>&at=<ms> from a
  // timeline row (which knows the pid but not the tree's DB id, so the graph resolves it to the node whose lifetime brackets ?at=).
  useEffect(() => {
    if (roots.length === 0) return;
    const processIdParam = searchParams.get("process");
    if (processIdParam) {
      const found = findNodeByDbId(roots, Number(processIdParam));
      if (found) setSelectedNode(found); // eslint-disable-line react-hooks/set-state-in-effect -- auto-select from URL
      return;
    }
    const pidQuery = searchParams.get("pid");
    const atQuery = searchParams.get("at");
    if (pidQuery && atQuery) {
      const atNs = Number(atQuery) * NANOSECONDS_PER_MILLISECOND;
      const found = findNodeByPidAtTime(roots, Number(pidQuery), atNs);
      if (found) setSelectedNode(found);
    }
  }, [roots, searchParams]);

  useEffect(() => {
    if (view !== "graph") return; // the timeline view does no graph work; the fetch (and the d3 draw below) are graph-only
    fetchTree(); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch on mount
  }, [fetchTree, view]);

  useEffect(() => {
    if (!svgRef.current) return;
    if (visibleRoots.length === 0) {
      d3.select(svgRef.current).selectAll("*").remove();
      layoutNodesRef.current = [];
      return;
    }
    // Clear any lingering tooltip before re-rendering: a collapse/expand can remove the hovered node without a mouseleave firing.
    // Disable set-state-in-effect for the synchronous reset, matching HostHealthPanel.
    /* eslint-disable react-hooks/set-state-in-effect */
    setHoverTip(null);
    /* eslint-enable react-hooks/set-state-in-effect */
    const result = renderTree(svgRef.current, visibleRoots, setSelectedNode, {
      alertProcessIds,
      collapsedIds,
      onToggleCollapsed: toggleCollapsed,
      expandedAggIds,
      onToggleAggExpanded: toggleAggExpanded,
      onHover: setHoverTip,
    });
    layoutNodesRef.current = result.nodes;
  }, [visibleRoots, alertProcessIds, collapsedIds, toggleCollapsed, expandedAggIds, toggleAggExpanded]);

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
    const inHorizontalView = nodeScreenX >= curLeft + TREE_MARGIN_PX
      && nodeScreenX <= curLeft + canvas.clientWidth - TREE_MARGIN_PX;
    const targetLeft = inHorizontalView ? curLeft : Math.max(0, nodeScreenX - canvas.clientWidth / 2);
    canvas.scrollTo({ top: targetTop, left: targetLeft, behavior: "smooth" });
  }, []);

  // Re-run highlighting whenever the query or the rendered tree changes.
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    const q = query.toLowerCase().trim();

    const { matches, pathNodes } = collectMatches(layoutNodesRef.current, q);
    matchesRef.current = matches;
    setMatchCount(matches.length);
    let targetIdx = 0;
    if (matches.length === 0) {
      setMatchIdx(0);
    } else {
      setMatchIdx((prev) => {
        targetIdx = prev < matches.length ? prev : 0;
        return targetIdx;
      });
    }

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

    // targetIdx is bounded by matches.length above; the bracket-access here
    // can't go out of range. eslint's plugin can't prove that.
    // eslint-disable-next-line security/detect-object-injection
    if (matches.length > 0) zoomToNode(matches[targetIdx]);
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
    globalThis.addEventListener("keydown", handler);
    return () => { globalThis.removeEventListener("keydown", handler); };
  }, []);

  const stepMatch = useCallback((delta: number) => {
    const total = matchesRef.current.length;
    if (total === 0) return;
    setMatchIdx((prev) => {
      const next = (prev + delta + total) % total;
      // next is bounded by total via the modulo above.
      // eslint-disable-next-line security/detect-object-injection
      zoomToNode(matchesRef.current[next]);
      return next;
    });
  }, [zoomToNode]);

  if (!hostId) return <p>No host selected.</p>;

  // viewHref toggles the view param while preserving the rest of the URL (window, alert anchor, selection), so switching views is a
  // link that never changes the shared time window. Graph is the default, so it drops ?view= rather than setting view=graph.
  const viewHref = (v: "graph" | "timeline"): string => {
    const next = new URLSearchParams(searchParams);
    if (v === "graph") {
      next.delete("view");
    } else {
      next.set("view", v);
    }
    const qs = next.toString();
    return `/hosts/${encodeURIComponent(hostId)}${qs ? `?${qs}` : ""}`;
  };

  const headerActions = (
    <div className="process-tree__controls">
      <div className="process-tree__viewtabs" role="tablist" aria-label="Host view">
        <Link to={viewHref("graph")} className="process-tree__viewtab" aria-current={view === "graph" ? "page" : undefined}>Graph</Link>
        <Link to={viewHref("timeline")} className="process-tree__viewtab" aria-current={view === "timeline" ? "page" : undefined}>Timeline</Link>
      </div>
      {view === "graph" && (
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
      )}
      <TimeRangeControl window={timeWindow} nowMs={nowMs} onChange={setTimeWindow} />
      {view === "graph" && (
        <>
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
          <label
            className="process-tree__toggle"
            title={flatten ? "Every process shown; repeated execs are not grouped" : "Repeated identical execs are grouped into ×N nodes"}
          >
            <input
              type="checkbox"
              className="process-tree__toggle-input"
              checked={flatten}
              onChange={(e) => { setFlatten(e.target.checked); }}
            />
            <span className="process-tree__toggle-switch" aria-hidden="true" />
            <span className="process-tree__toggle-label">Flatten</span>
          </label>
        </>
      )}
      <button type="button" className="process-tree__action-btn" onClick={() => { setNowMs(Date.now()); }}>
        Refresh
      </button>
    </div>
  );

  return (
    <>
      <HostHeader hostId={hostId} actions={headerActions} />

      {hostId ? <HostHealthPanel hostId={hostId} /> : null}

      {alertDetail && (
        <div className="alert-breadcrumb">
          <Link to="/alerts" className="alert-breadcrumb__back">&larr; Alerts</Link>
          <span className="alert-breadcrumb__sep">/</span>
          <span className="alert-breadcrumb__id">#{String(alertDetail.id)}</span>
          <Badge variant={SEVERITY_VARIANTS[alertDetail.severity] ?? "neutral"}>
            {alertDetail.severity}
          </Badge>
          {/* Render the alert title itself as a link to the rule's
              documentation page so an analyst standing in front of a
              fired alert can jump straight to "what does this rule do"
              without losing the process-tree context. The styling
              suppresses the default anchor underline + colour so the
              breadcrumb still reads as a label until the cursor lands
              on it. */}
          <Link
            to={`/rules/${encodeURIComponent(alertDetail.rule_id)}`}
            className="alert-breadcrumb__title alert-breadcrumb__title--link"
            title={`Open documentation for the ${alertDetail.rule_id} rule`}
          >
            {alertDetail.title}
          </Link>
          <span className="alert-breadcrumb__time">
            {new Date(alertDetail.created_at).toLocaleString()}
          </span>
          {/* Process-optional alerts have no chain to focus, so this generic chain toggle would be a confusing second control
              next to the info bar's widen/collapse button below. Show it only for process-backed alerts. */}
          {!isProcessOptionalAlert && (
            <>
              <span className="alert-breadcrumb__spacer" />
              <Button
                size="small"
                variant={focusAlertChain ? "primary" : "inverse"}
                onClick={() => { setFocusAlertChain((v) => !v); }}
                title={focusAlertChain
                  ? "Showing only the processes related to this alert; click to show the full host tree"
                  : "Showing the full host tree; click to focus the alert's process chain"}
              >
                {/* State label, not an action: both cases describe what's currently shown (the click action is in the
                    tooltip), so the toggle isn't read as "Show full tree" while it actually enables focus mode. */}
                {focusAlertChain ? "Focused on chain" : "Full host tree"}
              </Button>
            </>
          )}
        </div>
      )}

      {/* The finding detail (description + technique tags) is the "what and why" of the alert. It renders for every alert,
          and is the primary surface for a process-optional alert whose graph is intentionally empty. */}
      {alertDetail && (
        <div className="alert-detail-panel">
          <p className="alert-detail-panel__description">{alertDetail.description}</p>
          {alertDetail.techniques && alertDetail.techniques.length > 0 && (
            <div className="alert-detail-panel__techniques">
              {alertDetail.techniques.map((t) => (
                <Badge key={t} variant="neutral">{t}</Badge>
              ))}
            </div>
          )}
        </div>
      )}

      {/* The activity histogram describes the active window and is shared by both views (a click narrows the window either way). */}
      <ActivityHistogram
        hostId={hostId}
        fromNs={bounds.fromNs}
        toNs={bounds.toNs}
        onSelectBucket={(fromNs, toNs) => { setTimeWindow({ kind: "absolute", fromNs, toNs }); }}
      />

      {view === "timeline" ? (
        <HostTimeline hostId={hostId} bounds={bounds} emphasizePid={emphasizePid} />
      ) : (
        <>
          {loading && <p className="process-tree__status">Loading...</p>}
          {error && <p className="process-tree__status process-tree__status--error">Error: {error}</p>}
          {/* Process-optional alert: there is no attributed process chain, so this info bar is the SINGLE control for the graph
              (the generic chain toggle in the breadcrumb is hidden above). Focused: explain the empty graph + offer to widen.
              Widened: a short note + collapse back. Exactly one button in either state. */}
          {!loading && !error && isProcessOptionalAlert && (
            <div className="process-tree__status process-tree__status--info">
              {focusAlertChain ? (
                <>
                  <p>This detection isn’t attributed to a single process. See the detail above for what fired and why.</p>
                  <Button size="small" variant="inverse" onClick={() => { setFocusAlertChain(false); }}>
                    Show surrounding host activity
                  </Button>
                </>
              ) : (
                <>
                  <p>Showing the surrounding host activity for this detection.</p>
                  <Button size="small" variant="inverse" onClick={() => { setFocusAlertChain(true); }}>
                    Show alert detail only
                  </Button>
                </>
              )}
            </div>
          )}
          {!loading && !error && !isProcessOptionalAlert && roots.length === 0 && (
            <p className="process-tree__status">No processes in this time range.</p>
          )}

          <div className="process-tree__layout">
            <div className="process-tree__canvas">
              <svg ref={svgRef} />
              {hoverTip && (
                <div className="process-tree__tooltip" role="tooltip" style={{
                    left: Math.min(hoverTip.x + TOOLTIP_POINTER_OFFSET_PX, window.innerWidth - TOOLTIP_CLAMP_WIDTH_PX),
                    top: Math.min(hoverTip.y + TOOLTIP_POINTER_OFFSET_PX, window.innerHeight - TOOLTIP_CLAMP_HEIGHT_PX),
                  }}>
                  <div className="process-tree__tooltip-title">{hoverTip.tooltip.title}</div>
                  {hoverTip.tooltip.groupNote && <div className="process-tree__tooltip-group">{hoverTip.tooltip.groupNote}</div>}
                  <div className="process-tree__tooltip-cmdline">{hoverTip.tooltip.commandLine}</div>
                  {hoverTip.tooltip.verdictLabel && (
                    <div className={`process-tree__tooltip-verdict${hoverTip.tooltip.marked ? " process-tree__tooltip-verdict--marked" : ""}`}>
                      {hoverTip.tooltip.verdictLabel}
                    </div>
                  )}
                </div>
              )}
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
      )}
    </>
  );
}

// collectMatches walks the laid-out nodes and returns every node whose payload matches
// q (by name/path/pid/args) plus the set of nodes on the ancestor path of any match,
// used to dim non-matching subtrees while keeping the context to the match visible.
function collectMatches(
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

function isSystemPath(path: string): boolean {
  // Any .app bundle is a user-launchable application, so keep it visible even if it lives
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
// chain: the target, every ancestor back to the top root, and every descendant. If the
// target isn't in the tree, returns an empty set (the focus filter will then drop the whole
// tree, making it visually obvious that the target is out of range).
function findAlertChain(roots: ProcessNode[], targetDbId: number): Set<number> {
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
    if (n.pid === pid && n.fork_time_ns <= atNs && (n.exit_time_ns === undefined || n.exit_time_ns >= atNs)) {
      if (best === null || n.fork_time_ns > best.fork_time_ns) best = n;
    }
    for (const c of n.children ?? []) visit(c);
  };
  for (const n of nodes) visit(n);
  return best;
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
  interactions: TreeInteractions,
): RenderResult {
  const { alertProcessIds, collapsedIds, onToggleCollapsed, expandedAggIds, onToggleAggExpanded, onHover } = interactions;
  const hierarchy = toD3Hierarchy(roots);
  const root = d3.hierarchy(hierarchy);

  const treeLayout = d3.tree<D3Node>().nodeSize([TREE_NODE_HEIGHT_PX, TREE_NODE_WIDTH_PX]);
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

  const margin = TREE_MARGIN_PX;
  const svgHeight = maxX - minX + margin * 2;

  const sel = d3.select(svg);
  sel.selectAll("*").remove();
  sel.attr("height", svgHeight);

  const g = sel
    .append("g")
    .attr("transform", `translate(${String(margin - minY)},${String(margin - minX)})`);

  // Zoom behavior.
  const zoom = d3.zoom<SVGSVGElement, unknown>().scaleExtent([TREE_ZOOM_MIN, TREE_ZOOM_MAX]).on("zoom", (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
    g.attr("transform", String(event.transform));
  });
  sel.call(zoom);
  // eslint-disable-next-line @typescript-eslint/unbound-method
  sel.call(zoom.transform, d3.zoomIdentity.translate(margin - minY, margin - minX));

  // Links. Skip the synthetic-root edges: when there are multiple top-level
  // roots we add a parent node with pid=0 so d3.tree() has a single layout
  // anchor, but that node isn't drawn, and without this filter the edges
  // FROM that invisible parent show up in the canvas as ghost lines drifting
  // off the left side of the tree. The filter is gated on roots.length > 1
  // so a single real root with pid=0 (rare but legal) still gets its outgoing
  // edges drawn.
  const hasSyntheticRoot = roots.length > 1;
  g.selectAll("path.link")
    .data(links.filter((l) => !hasSyntheticRoot || l.source.depth !== 0))
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
    // node--evidence drives the amber ring via CSS (ProcessTree.scss) rather than presentation attributes, so the search-match
    // ring's class rule cannot silently override it (CSS rules beat SVG presentation attributes).
    .attr("class", (d) => (nodeEvidenceMarked(d.data.data) ? "node node--evidence" : "node"))
    .attr("transform", (d) => `translate(${String(d.y)},${String(d.x)})`)
    .style("cursor", "pointer")
    .on("click", (_, d) => {
      const p = d.data.data;
      // An aggregated "×N" node has no single process to inspect; clicking it expands the group to its sample instead of opening a
      // detail panel (issue #416). Sample children are ordinary process nodes, so their clicks fall through to onSelect.
      if (p.aggregated) {
        onToggleAggExpanded?.(p.id);
        return;
      }
      onSelect(p);
    })
    // Evidence tooltip (issue #580): positioned at the pointer on entry; not cursor-following, so hover costs one render, not one
    // per pixel. mouseleave clears it; the click-through detail panel remains the full surface.
    .on("mouseenter", (event: MouseEvent, d) => {
      onHover?.({ x: event.clientX, y: event.clientY, tooltip: buildNodeTooltip(d.data.data) });
    })
    .on("mouseleave", () => {
      onHover?.(null);
    });

  node
    .append("circle")
    .attr("class", "node__dot")
    // Alerted nodes get a larger red dot. The label sits far enough away from the
    // dot (see dx on the label text below) that neither the bigger dot nor the
    // search-match ring get clipped by the label backdrop.
    .attr("r", (d) => (alertProcessIds.has(d.data.data.id) ? NODE_DOT_RADIUS_ALERTED : NODE_DOT_RADIUS_DEFAULT))
    .attr("fill", (d) => {
      const p = d.data.data;
      if (alertProcessIds.has(p.id)) return "#ff5c83"; // core-vibrant-red
      // An aggregated group is "live" (green) when any member is still running; otherwise grey like a single exited process.
      if (p.aggregated) return p.aggregated.running_count > 0 ? "#009a7d" : "#8b8fa2";
      if (p.exit_time_ns) return "#8b8fa2";
      return "#009a7d";
    });

  // Collapse/expand chevron. Sits in front of the dot. Only rendered when a node has
  // children in the underlying data OR has been collapsed (so we can expand it back).
  // Click events on the chevron stop propagation so they don't also fire the node-select handler.
  const chevronNodes = node.filter((d) => {
    const p = d.data.data;
    if (p.aggregated) return true; // always expandable to its sample
    return (p.children !== undefined && p.children.length > 0) || collapsedIds.has(p.id);
  });
  chevronNodes
    .append("text")
    .attr("class", "node__chevron")
    .attr("dx", CHEVRON_DX)
    .attr("dy", CHEVRON_DY)
    .attr("font-size", "10px")
    .attr("font-family", "ui-monospace, SFMono-Regular, Menlo, monospace")
    .attr("fill", "#515774")
    .style("cursor", "pointer")
    .text((d) => {
      const p = d.data.data;
      if (p.aggregated) return expandedAggIds.has(p.id) ? "▼" : "▶";
      return collapsedIds.has(p.id) ? "▶" : "▼";
    })
    .on("click", (event: MouseEvent, d) => {
      event.stopPropagation();
      const p = d.data.data;
      if (p.aggregated) {
        onToggleAggExpanded?.(p.id);
        return;
      }
      onToggleCollapsed?.(p.id);
    });

  node
    .append("text")
    .attr("class", (d) => {
      const isAlerted = alertProcessIds.has(d.data.data.id);
      return `node__label${isAlerted ? " node__label--alert" : ""}`;
    })
    // dx=16 leaves enough gap that the label backdrop starts clear of an r=8
    // alert dot (extends to x=8) and of the r=7 + 2px stroke search-match ring
    // (extends to x=9), so neither is clipped by the backdrop rect.
    .attr("dx", LABEL_DX)
    .attr("dy", LABEL_DY)
    .attr("font-size", "12px")
    .attr("font-family", "ui-monospace, SFMono-Regular, Menlo, monospace")
    .attr("fill", (d) => (alertProcessIds.has(d.data.data.id) ? "#ff5c83" : "#192147"))
    .attr("font-weight", (d) => (alertProcessIds.has(d.data.data.id) ? "bold" : "normal"))
    .text((d) => {
      const p = d.data.data;
      // Aggregated nodes read as a group header ("grep ×1000"), not a single pid; the sample members carry the individual pids
      // once the node is expanded.
      if (p.aggregated) return `${d.data.name} ×${String(p.aggregated.count)}`;
      const base = `${d.data.name} (${String(d.data.pid)})`;
      const hidden = p._collapsedCount;
      return hidden && hidden > 0 ? `${base}  +${String(hidden)}` : base;
    });

  // White backdrop behind each label so sibling tree links passing through the
  // label area don't visually cut through the text. Inserted after the text is
  // drawn so we can size it from the text's actual bounding box, and inserted
  // BEFORE the text in the DOM so the text paints on top of the backdrop.
  node.each(function () {
    const g = d3.select(this);
    const textEl = g.select<SVGTextElement>("text.node__label").node();
    if (!textEl) return;
    const bbox = textEl.getBBox();
    g.insert("rect", "text.node__label")
      .attr("class", "node__label-bg")
      .attr("x", bbox.x - LABEL_BG_PAD_X)
      .attr("y", bbox.y - LABEL_BG_PAD_Y)
      .attr("width", bbox.width + LABEL_BG_EXTRA_WIDTH)
      .attr("height", bbox.height + LABEL_BG_EXTRA_HEIGHT)
      .attr("fill", "#fff")
      .attr("pointer-events", "none");
  });

  return { zoom, nodes };
}
