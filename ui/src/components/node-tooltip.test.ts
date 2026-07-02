import { describe, it, expect } from "vitest";

import { buildNodeTooltip, nodeEvidenceMarked } from "./node-tooltip";
import type { ProcessNode } from "../types";
import { CS_ADHOC } from "../signing";

function node(overrides: Partial<ProcessNode>): ProcessNode {
  return {
    id: 1,
    host_id: "h1",
    pid: 42,
    ppid: 1,
    path: "/usr/local/bin/tool",
    fork_time_ns: 100,
    exec_time_ns: 200,
    ...overrides,
  };
}

describe("buildNodeTooltip", () => {
  // spec:web-ui/process-node-conviction-evidence/hovering-a-node-shows-the-command-line-and-verdict
  it("shows the full command line and the Developer ID verdict", () => {
    const tip = buildNodeTooltip(
      node({
        args: ["/usr/local/bin/tool", "-ibck", "payload.zip"],
        code_signing: { team_id: "FDG8Q7N4CC", signing_id: "com.vendor.tool", flags: 0, is_platform_binary: false },
      }),
    );
    expect(tip.title).toBe("tool");
    expect(tip.commandLine).toBe("/usr/local/bin/tool -ibck payload.zip");
    expect(tip.verdictLabel).toBe("Developer ID (Team FDG8Q7N4CC)");
    expect(tip.marked).toBe(false);
    expect(tip.groupNote).toBeUndefined();
  });

  it("falls back to the path when no args were captured and marks an unsigned exec", () => {
    const tip = buildNodeTooltip(node({ args: undefined, code_signing: undefined }));
    expect(tip.commandLine).toBe("/usr/local/bin/tool");
    expect(tip.verdictLabel).toBe("unsigned");
    expect(tip.marked).toBe(true);
  });

  it("renders no verdict for a fork-only node (inherited image, not a conviction)", () => {
    const tip = buildNodeTooltip(node({ exec_time_ns: undefined, code_signing: undefined }));
    expect(tip.verdictLabel).toBeUndefined();
    expect(tip.marked).toBe(false);
  });

  // spec:web-ui/process-node-conviction-evidence/aggregated-node-hover-describes-the-group
  it("labels an aggregated node with the group size and the representative's evidence", () => {
    const tip = buildNodeTooltip(
      node({
        args: ["/usr/bin/grep", "-r", "needle"],
        code_signing: { team_id: "", signing_id: "com.apple.grep", flags: 0, is_platform_binary: true },
        aggregated: { count: 1000, exited_count: 990, running_count: 10, first_fork_ns: 1, last_fork_ns: 2 },
      }),
    );
    expect(tip.groupNote).toBe("×1000 processes (representative shown)");
    expect(tip.commandLine).toBe("/usr/bin/grep -r needle");
    expect(tip.verdictLabel).toBe("Apple platform");
  });
});

// spec:web-ui/process-node-conviction-evidence/unsigned-and-ad-hoc-nodes-are-marked-in-the-graph
describe("nodeEvidenceMarked", () => {
  it("marks unsigned and ad-hoc execs, not platform binaries or fork-only nodes", () => {
    expect(nodeEvidenceMarked(node({ code_signing: undefined }))).toBe(true);
    expect(
      nodeEvidenceMarked(
        node({ code_signing: { team_id: "", signing_id: "local", flags: CS_ADHOC, is_platform_binary: false } }),
      ),
    ).toBe(true);
    expect(
      nodeEvidenceMarked(
        node({ code_signing: { team_id: "", signing_id: "com.apple.zsh", flags: 0, is_platform_binary: true } }),
      ),
    ).toBe(false);
    expect(nodeEvidenceMarked(node({ exec_time_ns: undefined, code_signing: undefined }))).toBe(false);
  });
});
