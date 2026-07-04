import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render as rtlRender, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";
import { ProcessDetail } from "./ProcessDetail";
import { PermissionsProvider } from "../permissions";
import * as api from "../api";
import type { ProcessNode, ProcessDetail as ProcessDetailType, Alert, Command } from "../types";

// ProcessDetail now renders search-pivot <Link>s, so every render needs a router context. Wrap RTL's render so the existing call
// sites stay unchanged.
function render(ui: ReactElement) {
  return rtlRender(<MemoryRouter>{ui}</MemoryRouter>);
}

// ProcessDetail renders one process's metadata, its re-exec chain, network activity, and
// per-process alerts, plus the reauth-gated kill action. Tests pin the metadata fields,
// the close affordance, the loading→network transition, the re-exec chain, the alert
// status mutations, the kill happy path + poll-to-completion + failure, and the
// permission gate hiding the kill button.

const NS = 1_000_000;

function makeNode(over: Partial<ProcessNode> = {}): ProcessNode {
  return {
    id: 42,
    host_id: "h1",
    pid: 1234,
    ppid: 1,
    path: "/usr/bin/curl",
    fork_time_ns: 10 * NS,
    ...over,
  };
}

function makeDetail(over: Partial<ProcessDetailType> = {}): ProcessDetailType {
  return {
    process: makeNode(),
    network_connections: [],
    dns_queries: [],
    ...over,
  };
}

function makeAlert(over: Partial<Alert> = {}): Alert {
  return {
    id: 7,
    host_id: "h1",
    rule_id: "suspicious_exec",
    source: "detection",
    severity: "high",
    title: "Suspicious exec",
    description: "curl from a shell",
    process_id: 42,
    status: "open",
    created_at: "2026-06-24T00:00:00Z",
    updated_at: "2026-06-24T00:00:00Z",
    ...over,
  };
}

beforeEach(() => {
  vi.spyOn(api, "getProcessDetail").mockResolvedValue(makeDetail());
  vi.spyOn(api, "listAlertsByProcessId").mockResolvedValue([]);
  vi.spyOn(api, "updateAlertStatus").mockResolvedValue(undefined);
  vi.spyOn(api, "createCommand").mockResolvedValue({ id: 99 });
  vi.spyOn(api, "getCommand");
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("ProcessDetail metadata", () => {
  // spec:web-ui/process-detail-content/process-detail-surfaces-investigation-fields
  it("renders the core process fields and optional metadata when present", () => {
    render(
      <ProcessDetail
        hostId="h1"
        node={makeNode({
          args: ["curl", "https://evil.example"],
          uid: 501,
          gid: 20,
          sha256: "abc123",
          cdhash: "d".repeat(40),
          code_signing: { team_id: "T", signing_id: "com.apple.curl", flags: 1, is_platform_binary: true },
          exec_time_ns: 20 * NS,
          exit_time_ns: 30 * NS,
          exit_code: 1,
        })}
        onClose={vi.fn()}
      />,
    );
    expect(screen.getByText("1234")).toBeInTheDocument();
    expect(screen.getByText("/usr/bin/curl")).toBeInTheDocument();
    expect(screen.getByText("curl https://evil.example")).toBeInTheDocument();
    expect(screen.getByText("501")).toBeInTheDocument();
    expect(screen.getByText("abc123")).toBeInTheDocument();
    // The signing block renders as a derived verdict plus the raw identifiers; team id outranks the platform flag (issue #187).
    expect(screen.getByText("Developer ID (Team T)")).toBeInTheDocument();
    expect(screen.getByText("com.apple.curl")).toBeInTheDocument();
    expect(screen.getByText("T")).toBeInTheDocument();
    expect(screen.getByText("d".repeat(40))).toBeInTheDocument();
    expect(screen.getByText(/code 1/)).toBeInTheDocument();
  });

  // spec:web-ui/process-detail-content/verdict-distinguishes-the-signer-categories
  it("shows the unsigned verdict when no code-signing block was reported", () => {
    render(<ProcessDetail hostId="h1" node={makeNode({ exec_time_ns: 20 * NS })} onClose={vi.fn()} />);
    expect(screen.getByText("unsigned")).toBeInTheDocument();
  });

  it("shows no verdict for a fork-only node (inherited image, matching the tooltip's rule)", () => {
    render(<ProcessDetail hostId="h1" node={makeNode()} onClose={vi.fn()} />);
    expect(screen.queryByText("unsigned")).not.toBeInTheDocument();
    expect(screen.queryByText("Signing")).not.toBeInTheDocument();
  });

  // spec:web-ui/process-detail-content/evidence-fields-copy-in-one-click
  it("offers one-click copy for every evidence field", () => {
    render(
      <ProcessDetail
        hostId="h1"
        node={makeNode({
          args: ["curl", "https://evil.example"],
          sha256: "abc123",
          cdhash: "d".repeat(40),
          code_signing: { team_id: "T", signing_id: "com.apple.curl", flags: 1, is_platform_binary: true },
        })}
        onClose={vi.fn()}
      />,
    );
    for (const label of ["Copy command line", "Copy path", "Copy SHA256", "Copy cdhash", "Copy signing id", "Copy team id"]) {
      expect(screen.getByRole("button", { name: label })).toBeInTheDocument();
    }
  });

  // spec:web-ui/host-page-search-pivots/pivoting-from-a-hash-searches-the-fleet
  it("offers search-all-hosts pivots for the filterable artifacts", () => {
    render(
      <ProcessDetail
        hostId="h1"
        node={makeNode({
          path: "/usr/bin/curl",
          uid: 0,
          sha256: "abc123",
          exec_time_ns: 20 * NS,
          code_signing: { team_id: "T", signing_id: "com.apple.curl", flags: 1, is_platform_binary: true },
        })}
        onClose={vi.fn()}
      />,
    );
    expect(screen.getByRole("link", { name: "Search all hosts for this hash" })).toHaveAttribute("href", "/search?hash=abc123");
    expect(screen.getByRole("link", { name: "Search all hosts for this path" })).toHaveAttribute("href", "/search?path=%2Fusr%2Fbin%2Fcurl");
    expect(screen.getByRole("link", { name: "Search all hosts for this UID" })).toHaveAttribute("href", "/search?uid=0");
    // Team T + platform flag -> developer-id verdict; the pivot carries the verdict kind, not the raw signing id.
    expect(screen.getByRole("link", { name: "Search all hosts for this signing verdict" })).toHaveAttribute("href", "/search?signing=developer-id");
  });

  // spec:web-ui/host-page-search-pivots/unfilterable-artifacts-have-no-pivot
  it("does not pivot on signing id or team id (no server filter for them)", () => {
    render(
      <ProcessDetail
        hostId="h1"
        node={makeNode({ exec_time_ns: 20 * NS, code_signing: { team_id: "T", signing_id: "com.apple.curl", flags: 1, is_platform_binary: true } })}
        onClose={vi.fn()}
      />,
    );
    expect(screen.getByRole("button", { name: "Copy signing id" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /signing id/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /team id/i })).not.toBeInTheDocument();
  });

  it("falls back to (unknown) for an empty path", () => {
    render(<ProcessDetail hostId="h1" node={makeNode({ path: "" })} onClose={vi.fn()} />);
    expect(screen.getByText("(unknown)")).toBeInTheDocument();
  });

  it("invokes onClose when the close button is clicked", () => {
    const onClose = vi.fn();
    render(<ProcessDetail hostId="h1" node={makeNode()} onClose={onClose} />);
    fireEvent.click(screen.getByLabelText("Close"));
    expect(onClose).toHaveBeenCalledOnce();
  });
});

describe("ProcessDetail network + re-exec", () => {
  it("shows the loading message then the network section once detail resolves", async () => {
    render(<ProcessDetail hostId="h1" node={makeNode()} onClose={vi.fn()} />);
    expect(screen.getByText(/loading network data/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText(/no network activity/i)).toBeInTheDocument());
  });

  it("renders the re-exec chain with the prior-generation count and the current entry", async () => {
    vi.mocked(api.getProcessDetail).mockResolvedValue(
      makeDetail({
        re_exec_chain: [{ id: 1, host_id: "h1", pid: 1234, ppid: 1, path: "/bin/sh", fork_time_ns: 5 * NS, exec_time_ns: 6 * NS }],
      }),
    );
    render(<ProcessDetail hostId="h1" node={makeNode()} onClose={vi.fn()} />);
    await waitFor(() => expect(screen.getByText(/1 prior generation/i)).toBeInTheDocument());
    expect(screen.getByText("/bin/sh")).toBeInTheDocument();
    expect(screen.getByText(/current/i)).toBeInTheDocument();
  });
});

describe("ProcessDetail alerts", () => {
  it("renders per-process alerts and acknowledges an open alert", async () => {
    vi.mocked(api.listAlertsByProcessId).mockResolvedValue([makeAlert()]);
    render(<ProcessDetail hostId="h1" node={makeNode()} onClose={vi.fn()} />);
    await waitFor(() => expect(screen.getByText("Suspicious exec")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /acknowledge/i }));
    await waitFor(() => { expect(api.updateAlertStatus).toHaveBeenCalledWith(7, "acknowledged"); });
  });

  it("offers a reopen action for a resolved alert", async () => {
    vi.mocked(api.listAlertsByProcessId).mockResolvedValue([makeAlert({ status: "resolved" })]);
    render(<ProcessDetail hostId="h1" node={makeNode()} onClose={vi.fn()} />);
    await waitFor(() => expect(screen.getByText("Suspicious exec")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /acknowledge/i })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /reopen/i }));
    await waitFor(() => { expect(api.updateAlertStatus).toHaveBeenCalledWith(7, "open"); });
  });
});

describe("ProcessDetail kill action", () => {
  it("sends a kill command and polls to completion", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const completed: Command = {
      id: 99,
      host_id: "h1",
      command_type: "kill_process",
      payload: { pid: 1234 },
      status: "completed",
      created_at: "2026-06-24T00:00:00Z",
    };
    vi.mocked(api.getCommand).mockResolvedValue(completed);

    render(<ProcessDetail hostId="h1" node={makeNode()} onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: /kill process/i }));

    await waitFor(() => { expect(api.createCommand).toHaveBeenCalledWith("h1", "kill_process", { pid: 1234 }); });
    await screen.findByText("pending");

    await vi.advanceTimersByTimeAsync(2100);
    await waitFor(() => expect(screen.getByText(/process killed/i)).toBeInTheDocument());
  });

  it("shows a failed status when the kill command dispatch rejects", async () => {
    vi.mocked(api.createCommand).mockRejectedValue(new Error("dispatch failed"));
    render(<ProcessDetail hostId="h1" node={makeNode()} onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: /kill process/i }));
    await waitFor(() => expect(screen.getByText(/failed: failed to send command/i)).toBeInTheDocument());
  });

  it("hides the kill button when the operator lacks host.kill_process", () => {
    render(
      <PermissionsProvider permissions={[]}>
        <ProcessDetail hostId="h1" node={makeNode()} onClose={vi.fn()} />
      </PermissionsProvider>,
    );
    expect(screen.queryByRole("button", { name: /kill process/i })).not.toBeInTheDocument();
  });
});

// spec:web-ui/graph-and-timeline-cross-navigation/a-process-node-links-to-its-timeline-rows
describe("ProcessDetail show-in-timeline pivot (issue #583)", () => {
  it("links to the host timeline emphasizing this process's pid", async () => {
    render(<ProcessDetail hostId="host/A" node={makeNode({ pid: 1234 })} onClose={vi.fn()} />);
    const link = await screen.findByRole("link", { name: "Show in timeline" });
    expect(link).toHaveAttribute("href", "/hosts/host%2FA?view=timeline&pid=1234");
  });
});
