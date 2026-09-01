import { useEffect, useMemo, useRef, useState, useCallback, type RefObject } from "react";
import { useParams, useSearchParams, useLocation, Link } from "react-router";
import * as d3 from "d3";
import { fetchRuleDocs, getAlertDetail, getProcessTree, listAlerts } from "../api";
import type { AlertDetail, ProcessNode } from "../types";
import {
  NANOSECONDS_PER_MILLISECOND,
} from "../constants";
import { ProcessDetail } from "./ProcessDetail";
import { AlertTriageActions } from "./AlertTriageActions";
import { HostHeader } from "./HostHeader";
import { HostTimeline } from "./HostTimeline";
import { type NodeTooltip } from "./node-tooltip";
import { TechniqueTags } from "./TechniqueTags";
import { TimeRangeControl } from "./TimeRangeControl";
import { ActivityHistogram } from "./ActivityHistogram";
import { DEFAULT_ALERT_WINDOW_MS, DEFAULT_LIVE_WINDOW_MS, windowBounds, type TimeWindow } from "../timewindow";
import { Badge, type BadgeVariant } from "./ui/Badge";
import { Button } from "./ui/Button";
import {
  buildPreservedIds,
  buildQueryFilterIds,
  buildVisibleRoots,
  chainGenerations,
  collectMatches,
  wouldSystemToggleReveal,
  findAlertChain,
  resolveAlertEntry,
  selectNodeFromParams,
  viewHref,
  type D3Node,
  type D3PointNode,
} from "./ProcessTree.helpers";
import { renderTree, TREE_MARGIN_PX } from "./ProcessTree.render";
import "./ProcessTree.scss";

const SEVERITY_VARIANTS: Record<string, BadgeVariant> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

// Evidence tooltip layout (issue #580): how far the hover card sits from the pointer, and the room reserved so a card near the
// right/bottom viewport edge clamps back into view instead of rendering off-screen (width tracks the card's 34rem max-width).
const TOOLTIP_POINTER_OFFSET_PX = 14;
const TOOLTIP_CLAMP_WIDTH_PX = 560;
const TOOLTIP_CLAMP_HEIGHT_PX = 170;

const SHOW_SYSTEM_STORAGE_KEY = "edr.processTree.showSystem";

interface ProcessTreeViewProps {
  readonly hostId?: string;
  readonly entryAlert?: AlertDetail;
}

export function ProcessTreeView({ hostId: hostIdProp, entryAlert }: ProcessTreeViewProps = {}) {
  const params = useParams<{ hostId: string }>();
  // hostId is sourced from the prop first (the /alerts/:alertId route passes the alert's host), then the /hosts/:hostId route param.
  const hostId = hostIdProp ?? params.hostId ?? "";
  const [searchParams] = useSearchParams();
  const { pathname } = useLocation();
  // The active host-page view (issue #583): the process graph (default) or the flat event timeline. Held in the URL so a switch is
  // bookmarkable and the shared time window / alert anchor survive it.
  const view: "graph" | "timeline" = searchParams.get("view") === "timeline" ? "timeline" : "graph";
  // The process of interest carried across the graph<->timeline pivots: in the graph it selects the node (with ?at=), in the timeline
  // it emphasizes that process's rows.
  const pidParam = searchParams.get("pid");
  const emphasizePid = pidParam ? Number(pidParam) : undefined;
  // The alert context, folded from whichever entry path was used (the entryAlert prop on /alerts/:alertId, or the legacy
  // ?alert=&process=&at= query on the host route). Reading plain fields off this keeps the prop-or-query branching in one helper
  // instead of repeated inline at every use (Sonar S3776 on this function). atMs 0 = no anchor; focus = arrived from an alert.
  const alertEntry = resolveAlertEntry(entryAlert, searchParams);
  const anchorAtMs = alertEntry.atMs;
  const svgRef = useRef<SVGSVGElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const layoutNodesRef = useRef<D3PointNode[]>([]);
  const matchesRef = useRef<D3PointNode[]>([]);
  const [roots, setRoots] = useState<ProcessNode[]>([]);
  const [selectedNode, setSelectedNode] = useState<ProcessNode | null>(null);
  // The page's single time source (issue #581). Arriving from an alert anchors a wide window at the alert time (the alert-pivot
  // requirement's default); otherwise a live 1h window. Every consumer (tree fetch, histogram, control label) reads windowBounds
  // of this one value; a relative window's "now" is the frozen nowMs below, re-captured only by the Refresh action.
  const [timeWindow, setTimeWindow] = useState<TimeWindow>(() =>
    anchorAtMs > 0
      ? { kind: "relative", ms: DEFAULT_ALERT_WINDOW_MS, anchorNs: anchorAtMs * NANOSECONDS_PER_MILLISECOND }
      : { kind: "relative", ms: DEFAULT_LIVE_WINDOW_MS },
  );
  // The alert anchor arrives as the entryAlert prop (the /alerts/:alertId route) or the ?at= param on the host route. React Router
  // keeps this component mounted when the param changes (e.g. the alert breadcrumb's "back to host" link drops it), so re-derive the
  // entry window whenever the anchor transitions rather than only on mount. anchorAtMs is stable on the alert route, so this is a no-op
  // there and only fires on the host-route ?at= transitions.
  const lastAtMsRef = useRef<number>(anchorAtMs);
  useEffect(() => {
    if (lastAtMsRef.current === anchorAtMs) return;
    lastAtMsRef.current = anchorAtMs;
    setTimeWindow(
      anchorAtMs > 0
        ? { kind: "relative", ms: DEFAULT_ALERT_WINDOW_MS, anchorNs: anchorAtMs * NANOSECONDS_PER_MILLISECOND }
        : { kind: "relative", ms: DEFAULT_LIVE_WINDOW_MS },
    );
  }, [anchorAtMs]);

  // nowMs is the page's single frozen "now": captured once on mount and re-captured only on Refresh, never read live during render.
  // Every relative-window resolution (bounds here, the shift arrows, the absolute-picker draft) uses this one value, so a relative
  // window that has been on screen a while cannot resolve to a moving clock in one place and a stale one in another.
  const [nowMs, setNowMs] = useState(() => Date.now());
  // bounds is pure over (timeWindow, nowMs): both are state, so no clock read happens during render and there is no mount double-render.
  const bounds = useMemo(() => windowBounds(timeWindow, nowMs), [timeWindow, nowMs]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // truncation carries the two counts the "showing N of M" notice needs (issue #423), and is non-null ONLY when the server reported
  // the read as truncated. Storing null in the untruncated case rather than the counts plus a flag keeps the notice's presence
  // exactly equal to the server's own judgment, so the page cannot invent a warning the server did not raise.
  const [truncation, setTruncation] = useState<{ returned: number; totalMatched: number } | null>(null);
  const [alertProcessIds, setAlertProcessIds] = useState<Set<number>>(new Set());
  // techniquesByNodeId maps a process DB id to the deduped MITRE technique ids of its alerts (issue #585), so the hover tooltip can
  // show the technique mapping inline. Built from the same alert fetch that drives alertProcessIds.
  const [techniquesByNodeId, setTechniquesByNodeId] = useState<Map<number, string[]>>(new Map());
  // alertRefreshKey bumps to re-run the alert-badge fetch in place after a triage action on the alert header, so a resolved alert
  // loses its node dot + technique tag without a full host reload (the fetch keys on open + acknowledged, so resolving drops it).
  const [alertRefreshKey, setAlertRefreshKey] = useState(0);
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
  const [collapsedIds, setCollapsedIds] = useState<Set<number>>(new Set());
  // Aggregated "×N" nodes ship collapsed; expanding one materializes its capped sample as children in place (issue #416). Keyed by
  // the aggregated node's representative row id.
  const [expandedAggIds, setExpandedAggIds] = useState<Set<number>>(new Set());
  // Alert focus mode: when we arrived from an alert link, the tree defaults to showing only
  // the alerted process plus its ancestors and descendants (the "related processes only" view), so
  // the analyst isn't wading through a forest of unrelated background daemons. Toggleable.
  const [focusAlertChain, setFocusAlertChain] = useState<boolean>(() => alertEntry.focus);
  const [alertDetail, setAlertDetail] = useState<AlertDetail | null>(entryAlert ?? null);

  // A process-optional alert (process_id === 0) has no attributed process node to focus on: it keys on an artifact, not a
  // process (e.g. a LaunchDaemon registration, where the BTM instigator is Apple's smd, not the actor). Focus mode would
  // filter the forest to an empty chain and render a silent blank canvas, so these alerts get an explicit explanation +
  // opt-in expansion instead. We key on the ?process=0 URL param FIRST (it mirrors process_id and is available on the very
  // first render) so the explanation shows immediately: the focus filter already empties the forest from that same param on
  // mount, so deriving this from the async alertDetail alone would leave a blank canvas during the fetch (or permanently if
  // getAlertDetail fails) before the explanation appears. alertDetail.process_id is the fallback for any path that omits the
  // param.
  const isProcessOptionalAlert = entryAlert
    ? entryAlert.process_id === 0
    : searchParams.get("process") === "0" || (alertDetail !== null && alertDetail.process_id === 0);

  useEffect(() => {
    try { localStorage.setItem(SHOW_SYSTEM_STORAGE_KEY, String(showSystem)); } catch { /* ignore */ }
  }, [showSystem]);

  // Rule ids the catalog documents, used to decide whether the alert title can link anywhere. Null while loading or on failure,
  // which the link check treats as "cannot confirm", so a failed fetch degrades to plain text rather than to a broken link.
  const [documentedRuleIDs, setDocumentedRuleIDs] = useState<Set<string> | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchRuleDocs()
      .then((rules) => { if (!cancelled) setDocumentedRuleIDs(new Set(rules.map((r) => r.id))); })
      .catch(() => { if (!cancelled) setDocumentedRuleIDs(null); });
    return () => { cancelled = true; };
  }, []);

  // Fetch the alert so we can render a breadcrumb with title/severity/timestamp. Skipped when entryAlert is supplied: the
  // /alerts/:alertId route already fetched it and seeded alertDetail, so the query-param fetch path only runs on the host route and
  // never clobbers the prop-seeded detail.
  useEffect(() => {
    if (entryAlert !== undefined) return;
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
  }, [searchParams, entryAlert]);

  // Compute the set of process row-ids that make up the alert chain:
  // the alerted process, every ancestor back to the root, and every descendant.
  // Used by the focus-mode filter to drop everything unrelated to the alert.
  const alertChainIds = useMemo(() => {
    // The alerted process id is alertEntry.processId (from the entryAlert prop or the ?process= param). A process-optional alert
    // (processId 0) has no chain to focus, so it falls through to null.
    if (!focusAlertChain || !alertEntry.processId) return null;
    return findAlertChain(roots, alertEntry.processId);
  }, [roots, focusAlertChain, alertEntry.processId]);

  // The alert chain's process generations (pid + pidversion), so the Timeline can scope to the same chain the Graph shows (the
  // "Alert chain / Full tree" toggle drives both). Non-null only when focused on a process-backed alert AND the chain has resolved from
  // the fetched tree; null otherwise means the Timeline shows the full host stream. A resolved-but-empty chain also yields the full
  // stream rather than blank.
  const alertChainGenerations = useMemo(() => {
    if (!alertChainIds) return null;
    const gens = chainGenerations(roots, alertChainIds);
    return gens.length > 0 ? gens : null;
  }, [roots, alertChainIds]);

  // Never hide processes that have alerts attached, or that sit on the ancestor path of one -
  // even if their binary is in a system path, the analyst context matters.
  const preservedIds = useMemo(() => buildPreservedIds(roots, alertProcessIds), [roots, alertProcessIds]);

  // Re-shape the raw tree according to the current filters (see buildVisibleRoots in ProcessTree.helpers): hide system-path nodes
  // unconditionally (except preserved), optionally restrict to the alert chain, and drop children of collapsed nodes while stashing the
  // hidden-count on the surviving parent so we can render it as "+N". While a search query is active, skip the collapse step so the user
  // never sees "0 matches" when a match is only hidden inside a collapsed subtree AND prune to just matches + ancestors so the canvas
  // isn't a wall of dimmed noise.
  const applyCollapse = query.trim() === "";
  const queryFilterIds = useMemo(() => buildQueryFilterIds(roots, query), [roots, query]);
  // Build both system-visibility variants so we can tell whether the toggle would change anything on THIS view. buildVisibleRoots with
  const visibleRoots = useMemo(
    () =>
      buildVisibleRoots(roots, {
        showSystem, collapsedIds, expandedAggIds, preservedIds, applyCollapse, alertChainIds, queryFilterIds,
      }),
    [roots, showSystem, collapsedIds, expandedAggIds, preservedIds, applyCollapse, alertChainIds, queryFilterIds],
  );
  // Only offer the toggle when flipping it actually changes the rendered tree; a dead control that does nothing is worse than no
  // control. A single boolean walk over the raw roots answers this without materializing the second (unrendered) tree on every keystroke.
  const systemToggleChangesView = useMemo(
    () => wouldSystemToggleReveal(roots, { preservedIds, alertChainIds, queryFilterIds, expandedAggIds }),
    [roots, preservedIds, alertChainIds, queryFilterIds, expandedAggIds],
  );

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
    // Pin the alerted process so the server never folds it into a sibling "×N" aggregate (issue #416 gives aggregated headers a synthetic
    // negative id the id-keyed paths cannot match). This keeps the alerted process a first-class node so the alert-chain filter and the
    // alert dot can find it by its real id even when it has identical siblings. 0 (no alert) sends no pin.
    getProcessTree(hostId, bounds.fromNs, bounds.toNs, undefined, alertEntry.processId || undefined)
      .then((res) => {
        if (cancelled) return;
        setRoots(res.roots);
        setTruncation(res.truncated ? { returned: res.returned, totalMatched: res.total_matched } : null);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Unknown error");
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [hostId, bounds, alertEntry.processId]);

  // Fetch this host's open + acknowledged alerts to mark nodes with an alert dot (by process DB id) and to map each node to its
  // alerts' MITRE technique ids for the inline tooltip tags (issue #585).
  // Clear on host change so a slow/failed fetch cannot leave the previous host's alert dots + tooltip techniques on this host. Kept
  // separate from the fetch effect below so an in-place refresh (alertRefreshKey) does not flash every dot off and back on.
  useEffect(() => {
    /* eslint-disable react-hooks/set-state-in-effect */
    setAlertProcessIds(new Set());
    setTechniquesByNodeId(new Map());
    /* eslint-enable react-hooks/set-state-in-effect */
  }, [hostId]);

  useEffect(() => {
    if (!hostId) return;
    let cancelled = false;
    Promise.all([
      // Per-request catch so one failing status still marks nodes from the other; the badges are best-effort.
      listAlerts({ host_id: hostId, status: "open", limit: 1000 }).catch(() => []),
      listAlerts({ host_id: hostId, status: "acknowledged", limit: 1000 }).catch(() => []),
    ])
      .then(([open, acked]) => {
        if (cancelled) return;
        const ids = new Set<number>();
        const techniques = new Map<number, string[]>();
        for (const a of [...open, ...acked]) {
          ids.add(a.process_id);
          for (const t of a.techniques ?? []) {
            const existing = techniques.get(a.process_id) ?? [];
            if (!existing.includes(t)) existing.push(t);
            techniques.set(a.process_id, existing);
          }
        }
        setAlertProcessIds(ids);
        setTechniquesByNodeId(techniques);
      })
      .catch(() => { /* alert badges are best-effort */ });
    return () => { cancelled = true; };
  }, [hostId, alertRefreshKey]);

  // Auto-select a process from the URL: ?process=<dbId> (alert list / fleet search) or ?pid=<pid>&at=<ms> (a timeline row, which
  // knows the pid but not the DB id). The resolution lives in selectNodeFromParams so this effect stays a single branch.
  useEffect(() => {
    const found = selectNodeFromParams(roots, searchParams, entryAlert?.process_id);
    if (found) setSelectedNode(found); // eslint-disable-line react-hooks/set-state-in-effect -- auto-select from URL
  }, [roots, searchParams, entryAlert]);

  useEffect(() => {
    // Fetch the tree for the graph, and also when focused on an alert in the timeline view so the chain's pids resolve to scope the
    // timeline (the d3 draw below is a no-op in timeline view because the graph's svg is not mounted). Return fetchTree's cleanup so its
    // stale-response guard fires: on a window/host/pin change the prior in-flight fetch is cancelled and cannot paint a stale tree.
    if (view !== "graph" && !(focusAlertChain && alertEntry.processId)) return undefined;
    return fetchTree(); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch on mount
  }, [fetchTree, view, focusAlertChain, alertEntry.processId]);

  useEffect(() => {
    if (!svgRef.current) return;
    if (visibleRoots.length === 0) {
      d3.select(svgRef.current).selectAll("*").remove();
      layoutNodesRef.current = [];
      return;
    }
    // Clear any lingering tooltip before re-rendering: a collapse/expand can remove the hovered node without a mouseleave firing.
    // Disable set-state-in-effect for the synchronous reset, matching HostHeader.
    /* eslint-disable react-hooks/set-state-in-effect */
    setHoverTip(null);
    /* eslint-enable react-hooks/set-state-in-effect */
    const result = renderTree(svgRef.current, visibleRoots, setSelectedNode, {
      alertProcessIds,
      techniquesByNodeId,
      onToggleCollapsed: toggleCollapsed,
      expandedAggIds,
      onToggleAggExpanded: toggleAggExpanded,
      onHover: setHoverTip,
    });
    layoutNodesRef.current = result.nodes;
  }, [visibleRoots, alertProcessIds, techniquesByNodeId, toggleCollapsed, expandedAggIds, toggleAggExpanded]);

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

  // Header controls are the ones shared by both views: the Graph/Timeline switch, the time window, and Refresh. The graph-only search
  // and display toggles moved out of the header into the graphControls bar directly above the canvas (below), so each view's filters sit
  // with the content they shape (mirroring the timeline's filter row above its list) and the header reads the same in either view.
  const headerActions = (
    <div className="process-tree__controls">
      {/* Simple view navigation, not an ARIA tablist: the children are links with aria-current, not tab widgets with keyboard
          semantics, so a nav with aria-current is the honest role. */}
      <nav className="process-tree__viewtabs" aria-label="Host view">
        <Link to={viewHref(pathname, searchParams, "graph")} className="process-tree__viewtab" aria-current={view === "graph" ? "page" : undefined}>Graph</Link>
        <Link to={viewHref(pathname, searchParams, "timeline")} className="process-tree__viewtab" aria-current={view === "timeline" ? "page" : undefined}>Timeline</Link>
      </nav>
      <TimeRangeControl window={timeWindow} nowMs={nowMs} onChange={setTimeWindow} />
      <button type="button" className="process-tree__action-btn" onClick={() => { setNowMs(Date.now()); }}>
        Refresh
      </button>
    </div>
  );

  // The graph's filter bar: search + display toggles, rendered directly above the canvas in the graph branch (below). Placed here with
  // the rest of the search/toggle state so no prop-drilling into GraphBody is needed.
  const graphControls = (
    <div className="process-tree__graph-controls">
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
      {/* Only offer the toggle when it would change the rendered tree. On an alert chain whose only system-path nodes are the alerted
          process and its ancestors (kept regardless), flipping it does nothing, so a dead switch is hidden rather than shown. */}
      {systemToggleChangesView && (
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
      )}
    </div>
  );

  return (
    <>
      <HostHeader hostId={hostId} actions={headerActions} />

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
              on it.

              Linked ONLY when the catalog documents the rule. Not every
              alert's rule_id names a documented rule: an application-control
              alert carries the matched policy rule (`app_control:<n>`), which
              has never been in the catalog, and a non-detection such as
              sensor_recovery_failed is registered and alerts but is
              deliberately absent from it. Linking those lands the analyst on
              "Unknown rule", which is worse than no link, so the title falls
              back to plain text. */}
          {documentedRuleIDs?.has(alertDetail.rule_id) ? (
            <Link
              to={`/rules/${encodeURIComponent(alertDetail.rule_id)}`}
              className="alert-breadcrumb__title alert-breadcrumb__title--link"
              title={`Open documentation for the ${alertDetail.rule_id} rule`}
            >
              {alertDetail.title}
            </Link>
          ) : (
            <span className="alert-breadcrumb__title">{alertDetail.title}</span>
          )}
          {/* Attribution for the rule that raised this alert. The breadcrumb is the alert's detail view, so it is a surface
              displaying a match and carries the same licence obligation as the list. Unlike the rule link above it, this is
              rendered for every alert that records an origin, documented rule or not: crediting the author does not depend on
              whether we also happen to ship a doc page for their rule. Absent on alerts raised before migration 00012. */}
          {alertDetail.origin && (
            <span className="alert-breadcrumb__origin">{alertDetail.origin}</span>
          )}
          <span className="alert-breadcrumb__time">
            {new Date(alertDetail.created_at).toLocaleString()}
          </span>
          {/* Status + triage sit in the alert header itself (next to its id/severity/title), the industry-standard place for a
              detection's lifecycle controls, rather than floating on their own row below the description. */}
          <AlertTriageActions
            alertId={alertDetail.id}
            status={alertDetail.status}
            onStatusChange={(status) => {
              setAlertDetail((prev) => (prev ? { ...prev, status } : prev));
              // Re-fetch the tree's alert badges so a resolved alert loses its node dot + technique tag in place.
              setAlertRefreshKey((k) => k + 1);
            }}
          />
          {/* Process-optional alerts have no chain to focus, so this generic chain toggle would be a confusing second control
              next to the info bar's widen/collapse button below. Show it only for process-backed alerts. */}
          {!isProcessOptionalAlert && (
            <>
              <span className="alert-breadcrumb__spacer" />
              {/* Two-state scope switch as a segmented control (the industry-standard shape for a binary view toggle): both options are
                  visible and the active one is filled, so there is no ambiguity about whether a lone label names the current state or the
                  action it performs. Each segment sets its scope directly rather than flipping an opaque boolean. */}
              <div className="process-tree__scope" role="group" aria-label="Process scope">
                <button
                  type="button"
                  className={`process-tree__scope-item${focusAlertChain ? " process-tree__scope-item--active" : ""}`}
                  aria-pressed={focusAlertChain}
                  onClick={() => { setFocusAlertChain(true); }}
                  title="Show only the processes related to this alert (its ancestors and descendants)"
                >
                  Alert chain
                </button>
                <button
                  type="button"
                  className={`process-tree__scope-item${focusAlertChain ? "" : " process-tree__scope-item--active"}`}
                  aria-pressed={!focusAlertChain}
                  onClick={() => { setFocusAlertChain(false); }}
                  title="Show the full host process tree"
                >
                  Full tree
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {/* The finding detail is the "what and why" of the alert: its description and technique tags (linked to the rule doc). The
          alert's status + triage controls live in the header row above, next to its id/severity/title. This renders for every alert
          and is the primary surface for a process-optional alert whose graph is intentionally empty. */}
      {alertDetail && (
        <div className="alert-detail-panel">
          <p className="alert-detail-panel__description">{alertDetail.description}</p>
          <TechniqueTags techniques={alertDetail.techniques} ruleId={alertDetail.rule_id} className="alert-detail-panel__techniques" />
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
        <HostTimeline hostId={hostId} bounds={bounds} emphasizePid={emphasizePid} chainGenerations={alertChainGenerations ?? undefined} />
      ) : (
        <>
          {graphControls}
          <GraphBody
            hostId={hostId}
            loading={loading}
            error={error}
            isProcessOptionalAlert={isProcessOptionalAlert}
            focusAlertChain={focusAlertChain}
            onFocusAlertChain={setFocusAlertChain}
            rootsEmpty={roots.length === 0}
            truncation={truncation}
            svgRef={svgRef}
            hoverTip={hoverTip}
            selectedNode={selectedNode}
            onCloseDetail={() => { setSelectedNode(null); }}
            currentAlertId={alertDetail?.id}
          />
        </>
      )}
    </>
  );
}

interface GraphBodyProps {
  readonly hostId: string;
  readonly loading: boolean;
  readonly error: string | null;
  readonly isProcessOptionalAlert: boolean;
  readonly focusAlertChain: boolean;
  readonly onFocusAlertChain: (v: boolean) => void;
  readonly rootsEmpty: boolean;
  // truncation is non-null only when the server reported the read as truncated (issue #423).
  readonly truncation: { returned: number; totalMatched: number } | null;
  readonly svgRef: RefObject<SVGSVGElement | null>;
  readonly hoverTip: { x: number; y: number; tooltip: NodeTooltip } | null;
  readonly selectedNode: ProcessNode | null;
  readonly onCloseDetail: () => void;
  readonly currentAlertId?: number;
}

// GraphBody is the process-graph half of the host page: the fetch/status banners, the d3 canvas (drawn into svgRef by ProcessTreeView's
// effect), the hover tooltip, and the selected-process detail aside. Split out of ProcessTreeView (issue #583) so the graph's status
// conditionals don't nest under the graph/timeline view branch and inflate the parent's cognitive complexity.
function GraphBody({
  hostId, loading, error, isProcessOptionalAlert, focusAlertChain, onFocusAlertChain, rootsEmpty, truncation, svgRef, hoverTip,
  selectedNode, onCloseDetail, currentAlertId,
}: GraphBodyProps) {
  return (
    <>
      {loading && <p className="process-tree__status">Loading...</p>}
      {error && <p className="process-tree__status process-tree__status--error">Error: {error}</p>}
      {/* The window matched more processes than the server returned, so the graph below is partial. Without this the page renders a
          truncated tree that looks complete, and an analyst who sees no `curl` concludes there was no `curl` (issue #423). Phrasing
          and number formatting match the search results count so "showing N of M" reads the same across the product. */}
      {!loading && !error && truncation && (
        <p className="process-tree__status process-tree__status--info" role="status">
          Showing {truncation.returned.toLocaleString()} of {truncation.totalMatched.toLocaleString()} processes.
          Narrow the time range or use search to see the rest.
        </p>
      )}
      {/* Process-optional alert: there is no attributed process chain, so this info bar is the SINGLE control for the graph
          (the generic chain toggle in the breadcrumb is hidden above). Focused: explain the empty graph + offer to widen.
          Widened: a short note + collapse back. Exactly one button in either state. */}
      {!loading && !error && isProcessOptionalAlert && (
        <div className="process-tree__status process-tree__status--info">
          {focusAlertChain ? (
            <>
              <p>This detection isn’t attributed to a single process. See the detail above for what fired and why.</p>
              <Button size="small" variant="inverse" onClick={() => { onFocusAlertChain(false); }}>
                Show surrounding host activity
              </Button>
            </>
          ) : (
            <>
              <p>Showing the surrounding host activity for this detection.</p>
              <Button size="small" variant="inverse" onClick={() => { onFocusAlertChain(true); }}>
                Show alert detail only
              </Button>
            </>
          )}
        </div>
      )}
      {!loading && !error && !isProcessOptionalAlert && rootsEmpty && (
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
              {/* Technique tags are display-only here (issue #585): a hover tooltip disappears on mouse-out, so the clickable
                  /rules link lives on the detail panel; the tooltip just surfaces the mapping during the walk. */}
              {hoverTip.tooltip.techniques && (
                <div className="process-tree__tooltip-techniques">
                  <TechniqueTags techniques={hoverTip.tooltip.techniques} />
                </div>
              )}
            </div>
          )}
        </div>
        {selectedNode && (
          <aside className="process-tree__detail">
            <ProcessDetail hostId={hostId} node={selectedNode} onClose={onCloseDetail} currentAlertId={currentAlertId} />
          </aside>
        )}
      </div>
    </>
  );
}
