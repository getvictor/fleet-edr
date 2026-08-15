import type { ProcessNode, TreeResponse } from "../types";

// treeResponse wraps a forest in an untruncated TreeResponse (issue #423). Most process-tree tests care only about what renders, not
// about the result metadata, so this keeps them from restating three fields each and means a future field addition touches one place
// instead of every mock. Pass overrides to exercise the truncation notice, e.g.
// treeResponse(forest, { returned: 2000, total_matched: 2588, truncated: true }).
//
// The default counts are deliberately equal, which is the shape the server returns when nothing was dropped.
export function treeResponse(roots: ProcessNode[], overrides: Partial<TreeResponse> = {}): TreeResponse {
  const returned = roots.length;
  return { roots, returned, total_matched: returned, truncated: false, ...overrides };
}
