import { useEffect, useRef, useState, useCallback } from "react";
import { useParams, useSearchParams, Link } from "react-router-dom";
import * as d3 from "d3";
import { getProcessTree, listAlerts } from "../api";
import type { ProcessNode } from "../types";
import { ProcessDetail } from "./ProcessDetail";

const TIME_RANGES: { label: string; ms: number }[] = [
  { label: "15 min", ms: 15 * 60 * 1000 },
  { label: "1 hour", ms: 60 * 60 * 1000 },
  { label: "6 hours", ms: 6 * 60 * 60 * 1000 },
  { label: "24 hours", ms: 24 * 60 * 60 * 1000 },
];

export function ProcessTreeView() {
  const { hostId } = useParams<{ hostId: string }>();
  const [searchParams] = useSearchParams();
  const svgRef = useRef<SVGSVGElement>(null);
  const [roots, setRoots] = useState<ProcessNode[]>([]);
  const [selectedNode, setSelectedNode] = useState<ProcessNode | null>(null);
  const [rangeIdx, setRangeIdx] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [alertProcessIds, setAlertProcessIds] = useState<Set<number>>(new Set());

  const fetchTree = useCallback(() => {
    if (!hostId) return;
    setLoading(true);
    setError(null);

    const now = Date.now() * 1_000_000;
    const range = TIME_RANGES[rangeIdx];
    const from = now - range.ms * 1_000_000;

    getProcessTree(hostId, from, now)
      .then((res) => { setRoots(res.roots); })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Unknown error");
      })
      .finally(() => { setLoading(false); });
  }, [hostId, rangeIdx]);

  // Fetch alerts for this host to mark nodes with alert badges.
  useEffect(() => {
    if (!hostId) return;
    listAlerts({ host_id: hostId, status: "open" })
      .then((alerts) => {
        const ids = new Set(alerts.map((a) => a.process_id));
        // Also include acknowledged alerts.
        return listAlerts({ host_id: hostId, status: "acknowledged" }).then((acked) => {
          for (const a of acked) ids.add(a.process_id);
          setAlertProcessIds(ids);
        });
      })
      .catch(() => { /* alert badges are best-effort */ });
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
    if (roots.length === 0) {
      d3.select(svgRef.current).selectAll("*").remove();
      return;
    }
    renderTree(svgRef.current, roots, setSelectedNode, alertProcessIds);
  }, [roots, alertProcessIds]);

  if (!hostId) return <p>No host selected.</p>;

  return (
    <div>
      <div style={{ marginBottom: "1rem" }}>
        <Link to="/">&larr; Hosts</Link>
        <span style={{ margin: "0 1rem", color: "#666" }}>{hostId}</span>
        {TIME_RANGES.map((r, i) => (
          <button
            key={r.label}
            onClick={() => { setRangeIdx(i); }}
            style={{
              marginRight: "0.25rem",
              fontWeight: i === rangeIdx ? "bold" : "normal",
            }}
          >
            {r.label}
          </button>
        ))}
        <button onClick={fetchTree} style={{ marginLeft: "0.5rem" }}>
          Refresh
        </button>
      </div>

      {loading && <p>Loading...</p>}
      {error && <p style={{ color: "red" }}>Error: {error}</p>}
      {!loading && roots.length === 0 && <p>No processes in this time range.</p>}

      <div style={{ display: "flex", gap: "1rem" }}>
        <div style={{ flex: 1, overflow: "auto", border: "1px solid #ddd", borderRadius: 4 }}>
          <svg ref={svgRef} style={{ width: "100%", minHeight: 600 }} />
        </div>
        {selectedNode && (
          <div style={{ width: 400, flexShrink: 0 }}>
            <ProcessDetail hostId={hostId} node={selectedNode} onClose={() => { setSelectedNode(null); }} />
          </div>
        )}
      </div>
    </div>
  );
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
    return {
      name: basename(n.path) || `PID ${String(n.pid)}`,
      pid: n.pid,
      path: n.path,
      data: n,
      children: n.children?.map(convert),
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
  alertProcessIds: Set<number> = new Set()
) {
  const nodeHeight = 28;

  const hierarchy = toD3Hierarchy(roots);
  const root = d3.hierarchy(hierarchy);

  const treeLayout = d3.tree<D3Node>().nodeSize([nodeHeight, 220]);
  treeLayout(root);

  const nodes = root.descendants();
  const links = root.links();

  // Compute bounding box.
  let minY = Infinity, maxY = -Infinity;
  let minX = Infinity, maxX = -Infinity;
  for (const n of nodes) {
    const nx = n.x ?? 0;
    const ny = n.y ?? 0;
    if (nx < minX) minX = nx;
    if (nx > maxX) maxX = nx;
    if (ny < minY) minY = ny;
    if (ny > maxY) maxY = ny;
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
    .attr("stroke", "#999")
    .attr("stroke-width", 1)
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
    .attr("r", 5)
    .attr("fill", (d) => {
      if (d.data.data.exit_time_ns) return "#999";
      return "#4a90d9";
    });

  // Alert badge: red ring around nodes with open/acknowledged alerts.
  node
    .filter((d) => alertProcessIds.has(d.data.data.id))
    .append("circle")
    .attr("r", 9)
    .attr("fill", "none")
    .attr("stroke", "#d32f2f")
    .attr("stroke-width", 2);

  node
    .append("text")
    .attr("dx", 8)
    .attr("dy", 4)
    .attr("font-size", "12px")
    .attr("font-family", "monospace")
    .text((d) => `${d.data.name} (${String(d.data.pid)})`);
}
