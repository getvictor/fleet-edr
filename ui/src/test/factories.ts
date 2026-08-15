import type { ProcessNode, TreeResponse } from "../types";

// countAdmittedRows counts the process ROWS a forest represents, which is what the server's `returned` means: the rows its limit
// admitted, before aggregation folded any of them. That is not the same as the number of nodes: descendants count too.
//
// An aggregated node contributes its whole group size and the walk stops there. Its members are never separate rows to add on top:
// the server ships such a node childless, and once the UI expands one, buildVisibleRoots re-parents the capped `sample` under
// `children` while keeping `aggregated` set. Recursing in that state would count the sampled members twice.
function countAdmittedRows(nodes: ProcessNode[]): number {
  return nodes.reduce(
    (total, node) => total + (node.aggregated ? node.aggregated.count : 1 + countAdmittedRows(node.children ?? [])),
    0,
  );
}

// treeResponse wraps a forest in an untruncated TreeResponse (issue #423). Most process-tree tests care only about what renders, not
// about the result metadata, so this keeps them from restating three fields each and means a future field addition touches one place
// instead of every mock. Pass overrides to exercise the truncation notice, e.g.
// treeResponse(forest, { returned: 2000, total_matched: 2588, truncated: true }).
//
// The default counts are derived from the forest rather than fixed, so a default mock is a response the server could actually have
// produced: equal counts, and both equal to the rows the forest represents.
export function treeResponse(roots: ProcessNode[], overrides: Partial<TreeResponse> = {}): TreeResponse {
  const returned = countAdmittedRows(roots);
  return { roots, returned, total_matched: returned, truncated: false, ...overrides };
}
