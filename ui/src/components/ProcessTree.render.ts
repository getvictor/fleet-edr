// d3 rendering for ProcessTree.tsx (issue: consolidation cognitive-complexity paydown). This module owns the d3 DOM mutation: the tree
// layout, the zoom behavior, and the per-node circle/chevron/label drawing. Split out of ProcessTree.tsx so the component body stays a
// React/state file and the imperative d3 wiring lives on its own. The dependency is one-way: this module never imports from
// ProcessTree.tsx. Behavior is identical to the inlined original except the chevronGlyph condition is written positive-first.
import * as d3 from "d3";
import type { ProcessNode } from "../types";
import { toD3Hierarchy, type D3Node, type D3PointNode } from "./ProcessTree.helpers";
import { buildNodeTooltip, nodeEvidenceMarked, type NodeTooltip } from "./node-tooltip";

// d3 layout + render constants. Tuned by hand; collected here so a future
// "make labels bigger" change touches one block instead of every selector.
const TREE_NODE_HEIGHT_PX = 28;
const TREE_NODE_WIDTH_PX = 220;
export const TREE_MARGIN_PX = 40;
const TREE_ZOOM_MIN = 0.2;
const TREE_ZOOM_MAX = 3;
const NODE_DOT_RADIUS_DEFAULT = 5;
const NODE_DOT_RADIUS_ALERTED = 8;
const CHEVRON_DX = -14;
const CHEVRON_DY = 4;
const LABEL_DX = 16;
const LABEL_DY = 4;
const LABEL_BG_PAD_X = 3;
const LABEL_BG_PAD_Y = 1;
const LABEL_BG_EXTRA_WIDTH = LABEL_BG_PAD_X * 2;
const LABEL_BG_EXTRA_HEIGHT = LABEL_BG_PAD_Y * 2;

export interface RenderResult {
  zoom: d3.ZoomBehavior<SVGSVGElement, unknown>;
  nodes: D3PointNode[];
}

// TreeInteractions bundles the node-state + callbacks renderTree needs so its signature stays under the parameter cap. alertProcessIds
// drives the alert dot; onToggleCollapsed drives the generic subtree collapse (the chevron glyph derives collapsed-ness from each
// node's rendered _collapsedCount, so no collapsedIds set is threaded here); expandedAggIds/onToggleAggExpanded drive the issue-#416
// aggregated-node expand.
export interface TreeInteractions {
  alertProcessIds: Set<number>;
  // techniquesByNodeId maps a process DB id to its alerts' technique ids, shown in the hover tooltip (issue #585).
  techniquesByNodeId: Map<number, string[]>;
  onToggleCollapsed?: (nodeId: number) => void;
  expandedAggIds: Set<number>;
  onToggleAggExpanded?: (nodeId: number) => void;
  // onHover reports pointer entry/exit over a node so the component can render the evidence tooltip (issue #580); null clears it.
  onHover?: (hover: { x: number; y: number; tooltip: NodeTooltip } | null) => void;
}

// The pure per-node display derivations renderTree's d3 callbacks delegate to, so the render body below stays flat d3 wiring instead of
// nested branch logic (issue: complexity paydown). Each takes plain values, so it is side-effect-free and independently testable.

// computeLayoutBounds is the bounding box of the laid-out hierarchy, used to size the svg and center the initial zoom transform.
function computeLayoutBounds(nodes: D3PointNode[]): { minX: number; maxX: number; minY: number; maxY: number } {
  let minY = Infinity, maxY = -Infinity;
  let minX = Infinity, maxX = -Infinity;
  for (const n of nodes) {
    if (n.x < minX) minX = n.x;
    if (n.x > maxX) maxX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.y > maxY) maxY = n.y;
  }
  return { minX, maxX, minY, maxY };
}

// node--evidence drives the amber ring via CSS (ProcessTree.scss) rather than presentation attributes, so the search-match ring's class
// rule cannot silently override it (CSS rules beat SVG presentation attributes).
function evidenceNodeClass(p: ProcessNode): string {
  return nodeEvidenceMarked(p) ? "node node--evidence" : "node";
}

// Alerted nodes get a larger red dot. The label sits far enough from the dot (see LABEL_DX) that neither the bigger dot nor the
// search-match ring get clipped by the label backdrop.
function nodeDotRadius(alerted: boolean): number {
  return alerted ? NODE_DOT_RADIUS_ALERTED : NODE_DOT_RADIUS_DEFAULT;
}

function nodeDotFill(p: ProcessNode, alerted: boolean): string {
  if (alerted) return "#ff5c83"; // core-vibrant-red
  // An aggregated group is "live" (green) when any member is still running; otherwise grey like a single exited process.
  if (p.aggregated) return p.aggregated.running_count > 0 ? "#009a7d" : "#8b8fa2";
  if (p.exit_time_ns) return "#8b8fa2";
  return "#009a7d";
}

// A chevron is drawn when a node has visible children in the rendered tree OR is actually collapsed (so it can be expanded back). The
// authoritative "rendered collapsed" signal is _collapsedCount, which buildVisibleRoots sets only on nodes it truly collapses: a node
// whose id is in collapsedIds but whose children stay visible (search-expanded, applyCollapse off) has no _collapsedCount and reads as
// expanded. An aggregated node is always expandable to its sample.
function nodeHasChevron(p: ProcessNode): boolean {
  if (p.aggregated) return true; // always expandable to its sample
  return (p.children !== undefined && p.children.length > 0) || p._collapsedCount !== undefined;
}

function chevronGlyph(p: ProcessNode, expandedAggIds: Set<number>): string {
  if (p.aggregated) return expandedAggIds.has(p.id) ? "▼" : "▶";
  return p._collapsedCount === undefined ? "▼" : "▶";
}

function nodeLabelClass(alerted: boolean): string {
  return `node__label${alerted ? " node__label--alert" : ""}`;
}

function nodeLabelFill(alerted: boolean): string {
  return alerted ? "#ff5c83" : "#192147";
}

function nodeLabelWeight(alerted: boolean): string {
  return alerted ? "bold" : "normal";
}

function nodeLabelText(node: D3Node): string {
  const p = node.data;
  // Aggregated nodes read as a group header ("grep ×1000"), not a single pid; the sample members carry the individual pids once the
  // node is expanded.
  if (p.aggregated) return `${node.name} ×${String(p.aggregated.count)}`;
  const base = `${node.name} (${String(node.pid)})`;
  const hidden = p._collapsedCount;
  return hidden && hidden > 0 ? `${base}  +${String(hidden)}` : base;
}

export function renderTree(
  svg: SVGSVGElement,
  roots: ProcessNode[],
  onSelect: (node: ProcessNode) => void,
  interactions: TreeInteractions,
): RenderResult {
  const { alertProcessIds, techniquesByNodeId, onToggleCollapsed, expandedAggIds, onToggleAggExpanded, onHover } =
    interactions;
  const hierarchy = toD3Hierarchy(roots);
  const root = d3.hierarchy(hierarchy);

  const treeLayout = d3.tree<D3Node>().nodeSize([TREE_NODE_HEIGHT_PX, TREE_NODE_WIDTH_PX]);
  treeLayout(root);

  const nodes = root.descendants() as D3PointNode[];
  const links = root.links();

  // Compute bounding box.
  const { minX, maxX, minY } = computeLayoutBounds(nodes);

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
    .attr("class", (d) => evidenceNodeClass(d.data.data))
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
      onHover?.({ x: event.clientX, y: event.clientY, tooltip: buildNodeTooltip(d.data.data, techniquesByNodeId.get(d.data.data.id)) });
    })
    .on("mouseleave", () => {
      onHover?.(null);
    });

  node
    .append("circle")
    .attr("class", "node__dot")
    .attr("r", (d) => nodeDotRadius(alertProcessIds.has(d.data.data.id)))
    .attr("fill", (d) => nodeDotFill(d.data.data, alertProcessIds.has(d.data.data.id)));

  // Collapse/expand chevron. Sits in front of the dot. Only rendered when a node has visible children in the rendered tree OR is
  // actually collapsed (its _collapsedCount is set, so we can expand it back). Click events on the chevron stop propagation so they
  // don't also fire the node-select handler.
  const chevronNodes = node.filter((d) => nodeHasChevron(d.data.data));
  chevronNodes
    .append("text")
    .attr("class", "node__chevron")
    .attr("dx", CHEVRON_DX)
    .attr("dy", CHEVRON_DY)
    .attr("font-size", "10px")
    .attr("font-family", "ui-monospace, SFMono-Regular, Menlo, monospace")
    .attr("fill", "#515774")
    .style("cursor", "pointer")
    .text((d) => chevronGlyph(d.data.data, expandedAggIds))
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
    .attr("class", (d) => nodeLabelClass(alertProcessIds.has(d.data.data.id)))
    // dx=16 leaves enough gap that the label backdrop starts clear of an r=8
    // alert dot (extends to x=8) and of the r=7 + 2px stroke search-match ring
    // (extends to x=9), so neither is clipped by the backdrop rect.
    .attr("dx", LABEL_DX)
    .attr("dy", LABEL_DY)
    .attr("font-size", "12px")
    .attr("font-family", "ui-monospace, SFMono-Regular, Menlo, monospace")
    .attr("fill", (d) => nodeLabelFill(alertProcessIds.has(d.data.data.id)))
    .attr("font-weight", (d) => nodeLabelWeight(alertProcessIds.has(d.data.data.id)))
    .text((d) => nodeLabelText(d.data));

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
