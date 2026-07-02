import type { ProcessNode } from "../types";
import { deriveSigningVerdict, isEvidenceMarked } from "../signing";
import { formatCommandLine } from "../cmdline";

// NodeTooltip is the hover content for a process node (issue #580): the conviction evidence an analyst reads while walking a chain,
// without opening the detail panel. Built by a pure function so the enrolled/unsigned/aggregated shapes are testable without
// simulating D3 hover geometry.
export interface NodeTooltip {
  title: string;
  commandLine: string;
  // verdictLabel is absent for a fork-only node: a process that has not exec'd yet runs its parent's inherited image, so it carries
  // no code-signing block of its own and calling it "unsigned" would be a false conviction.
  verdictLabel?: string;
  marked: boolean;
  groupNote?: string;
}

export function buildNodeTooltip(p: ProcessNode): NodeTooltip {
  const verdict = p.exec_time_ns ? deriveSigningVerdict(p.code_signing) : undefined;
  return {
    title: basename(p.path) || `PID ${String(p.pid)}`,
    commandLine: formatCommandLine(p.args, p.path),
    verdictLabel: verdict?.label,
    marked: verdict !== undefined && isEvidenceMarked(verdict),
    // An aggregated node collapses identical-path siblings; the group key includes binary identity, so the representative's command
    // line and verdict describe the members. Say so rather than pretending the tooltip covers each one individually.
    groupNote: p.aggregated ? `×${String(p.aggregated.count)} processes (representative shown)` : undefined,
  };
}

// nodeEvidenceMarked reports whether the graph should draw the amber evidence ring on this node: an exec'd process whose verdict is
// ad-hoc or unsigned. Fork-only nodes are never marked (see NodeTooltip.verdictLabel).
export function nodeEvidenceMarked(p: ProcessNode): boolean {
  if (!p.exec_time_ns) return false;
  return isEvidenceMarked(deriveSigningVerdict(p.code_signing));
}

function basename(path: string): string {
  // Both separators: Windows hosts are landing (ADR-0018) and their paths use backslashes.
  const idx = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return idx >= 0 ? path.slice(idx + 1) : path;
}
