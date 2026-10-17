import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, fireEvent, within } from "@testing-library/react";
import { MemoryRouter, Routes, Route, Link } from "react-router";

import { SessionView } from "./SessionView";
import * as api from "../../api";
import { proc, realSession, SESSION } from "../../test/agentSession";
import type { AgentSessionSummary, Alert, ProcessNode, TreeResponse } from "../../types";

function tree(over: Partial<TreeResponse> = {}): TreeResponse {
  return { roots: realSession(), returned: 16, total_matched: 16, total_matched_capped: false, truncated: false, ...over };
}

function renderView() {
  return render(
    <MemoryRouter initialEntries={[`/agent-sessions/H1/${SESSION}`]}>
      <Routes>
        <Route path="/agent-sessions/:hostId/:sessionId" element={<SessionView />} />
      </Routes>
    </MemoryRouter>,
  );
}

// names returns the process names listed in an element, in order. A process's name is the button that selects it.
function names(el: HTMLElement): (string | null)[] {
  return within(el).queryAllByRole("button", { pressed: false }).map((b) => b.textContent);
}

// callHeaders returns the tool-call group headers, in the order the page lists them.
function callHeaders(): HTMLElement[] {
  return screen.getAllByRole("button", { expanded: true });
}

// The record, alert and tool-call reads decorate the tree; by default the session has no record, alerts or calls, and each test
// overrides what it is about.
beforeEach(() => {
  vi.spyOn(api, "listAgentSessions").mockResolvedValue({ rows: [], total_matched: 0 });
  vi.spyOn(api, "listAlerts").mockResolvedValue([]);
  vi.spyOn(api, "getAgentToolCalls").mockResolvedValue({ tool_calls: [], truncated: false });
  vi.spyOn(api, "getAgentSessionLineage").mockResolvedValue({ forked_session_ids: [] });
});

// A /fork is a session of its own, linked both ways to the session it was forked from (issue #1347).
describe("SessionView lineage", () => {
  const PARENT = "5828cd24-efb7-4b7b-a5bf-f3b24681ba10";
  const FORKS = ["bd46ed99-3433-4752-9f0f-9f8945e0305a", "c1a2b3c4-0000-4000-8000-000000001347"];

  // spec:web-ui/forked-session-lineage/a-forked-session-links-to-its-parent-and-its-forks
  it("links the session it was forked from and the sessions forked from it", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    const spy = vi.spyOn(api, "getAgentSessionLineage").mockResolvedValue({ forked_from_session_id: PARENT, forked_session_ids: FORKS });
    renderView();
    const parent = await screen.findByRole("link", { name: `Session ${PARENT}` });
    expect(parent).toBeVisible();
    expect(parent).toHaveAttribute("href", `/agent-sessions/H1/${PARENT}`);
    expect(parent.closest("span")).toHaveTextContent(/^Forked from Session 5828cd24/);
    for (const fork of FORKS) {
      expect(screen.getByRole("link", { name: `Session ${fork}` })).toHaveAttribute("href", `/agent-sessions/H1/${fork}`);
    }
    expect(screen.getByText(/Forked into/)).toBeVisible();
    expect(spy).toHaveBeenCalledWith("H1", SESSION);
  });

  it("shows no lineage for a session neither forked nor forked from, or when the read fails", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    vi.spyOn(api, "getAgentSessionLineage").mockRejectedValue(new Error("down"));
    renderView();
    expect(await screen.findAllByRole("button", { expanded: true })).not.toHaveLength(0);
    expect(screen.queryByText(/Forked (from|into)/)).toBeNull();
  });

  it("shows only the forks of a session that was not itself forked", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    vi.spyOn(api, "getAgentSessionLineage").mockResolvedValue({ forked_session_ids: [FORKS[0]] });
    renderView();
    expect(await screen.findByRole("link", { name: `Session ${FORKS[0]}` })).toBeVisible();
    expect(screen.queryByText(/Forked from/)).toBeNull();
  });
});

// lsActivity is a session activity read naming the capture's ls (row 2298323) as the one process that connected anywhere.
const lsActivity = {
  files: { events: 0, distinct: 0, truncated: false, rows: [] },
  network: {
    events: 1, distinct: 1, truncated: false,
    rows: [{ pid: 80728, pidversion: 7, count: 1, first_ns: 1, last_ns: 1, remote_address: "1.1.1.1", remote_port: 443, protocol: "tcp" }],
  },
  dns: { events: 0, distinct: 0, truncated: false, rows: [] },
  scope: { applied: true, processes: 16, unmatched: 0, truncated: false },
  processes: [{ id: 2298323, pid: 80728, pidversion: 7, path: "/bin/ls" }],
};

afterEach(() => { vi.restoreAllMocks(); });

function record(over: Partial<AgentSessionSummary> = {}): AgentSessionSummary {
  return {
    host_id: "H1",
    agent_session_id: SESSION,
    agent_name: "claude-code",
    agent_version: "2.1.296",
    agent_pid: 80673,
    cwd: "/Users/dev/project",
    first_seen_ns: 50_000_000,
    last_seen_ns: 400_000_000_000,
    process_count: 16,
    alert_count: 1,
    ...over,
  };
}

function alert(over: Partial<Alert>): Alert {
  return {
    id: 2047,
    host_id: "H1",
    rule_id: "discovery",
    source: "detection",
    severity: "high",
    title: "System discovery",
    description: "d",
    process_id: 2298323,
    status: "open",
    created_at: "2026-10-13T09:37:07Z",
    ...over,
  } as Alert;
}

// manyCalls is a session of n tool calls, each one wrapper shell running one command, numbered from 0.
function manyCalls(n: number): ProcessNode[] {
  return Array.from({ length: n }, (_, i) => proc(10 * (i + 1), 1000 + i, 100 * (i + 1), "/bin/zsh",
    ["/bin/zsh", "-c", `eval 'step ${String(i)}'`],
    [proc(10 * (i + 1) + 1, 2000 + i, 100 * (i + 1) + 1, "/bin/echo", ["echo", String(i)])], { tool_call_group: 1000 + i }));
}

describe("SessionView", () => {
  // spec:web-ui/tool-calls-beside-their-processes/each-bash-group-shows-its-tool-call
  // spec:web-ui/tool-calls-beside-their-processes/calls-that-cannot-be-told-apart-are-marked-ambiguous
  // spec:web-ui/observed-commands-and-reported-tool-calls-are-named-apart/a-reported-tool-call-is-labelled-as-the-agent-s
  it("shows each command's reported tool call, and calls it cannot tell apart as ambiguous", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: manyCalls(3) }));
    const call = (id: string, command: string, at: number, description?: string) =>
      ({ tool_use_id: id, tool_name: "Bash", command, called_at_ns: at, description, uid: 501 });
    const spy = vi.spyOn(api, "getAgentToolCalls").mockResolvedValue({
      tool_calls: [call("toolu_a", "step 0", 90, "First step"), call("toolu_b", "step 1", 190), call("toolu_c", "step 1", 190)],
      truncated: false,
    });
    renderView();
    const headers = await screen.findAllByRole("button", { expanded: true });
    expect(spy).toHaveBeenCalledWith("H1", SESSION);
    expect(within(headers[0]).getByText("First step")).toBeVisible();
    expect(within(headers[0]).getByText("toolu_a")).toBeVisible();
    // Both the paired call and the ambiguous one say they are the agent's report; the unpaired command says nothing.
    expect(within(headers[0]).getByText("Reported by agent")).toBeVisible();
    expect(within(headers[1]).getByText("Reported by agent")).toBeVisible();
    // Both labels say where the report comes from: the outer title on an ambiguous call names its candidates instead.
    for (const header of headers.slice(0, 2)) {
      expect(within(header).getByText("Reported by agent")).toHaveAttribute("title", expect.stringContaining("not observed by the sensor"));
    }
    expect(within(headers[2]).queryByText("Reported by agent")).toBeNull();
    const ambiguous = within(headers[1]).getByText(/One of 2 identical calls made at once/);
    expect(ambiguous).toBeVisible();
    expect(ambiguous).toHaveAttribute("title", "One of: toolu_b, toolu_c");
    expect(within(headers[2]).queryByText(/toolu_/)).toBeNull();
  });

  it("says when the agent reported more tool calls than were read", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: manyCalls(1) }));
    vi.spyOn(api, "getAgentToolCalls").mockResolvedValue({ tool_calls: [], truncated: true });
    renderView();
    expect(await screen.findByText(/reported more tool calls than are read/)).toBeVisible();
  });

  it("lists the calls without their tool calls when the transcript read fails", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: manyCalls(2) }));
    vi.spyOn(api, "getAgentToolCalls").mockRejectedValue(new Error("down"));
    renderView();
    expect(await screen.findAllByRole("button", { expanded: true })).toHaveLength(2);
    expect(screen.queryByText(/toolu_/)).toBeNull();
  });

  // spec:web-ui/ai-agent-session-view/tool-calls-are-labelled-with-the-command-the-agent-ran
  it("reads the session and lists one group per tool call, labelled with its command", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([{ host_id: "H1", hostname: "qa-1280-vm" } as never]);
    const spy = vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    renderView();
    expect(await screen.findByRole("heading", { name: "claude-code 2.1.296" })).toBeVisible();
    expect(spy).toHaveBeenCalledWith("H1", SESSION);
    expect(callHeaders().map((h) => h.querySelector("code")?.textContent)).toEqual([
      "ls /private/tmp | head -3",
      "(sleep 47 &)",
      "nohup sleep 48 >/dev/null 2>&1 &",
      "env -i /bin/echo qa1280",
      `/bin/sh -c "sleep 1; echo qa1280-done"`,
    ]);
    expect(screen.getByText("/private/tmp")).toBeVisible();
    expect(await screen.findByText("qa-1280-vm")).toBeVisible();
    expect(screen.getByText("16 processes")).toBeVisible();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  // spec:web-ui/ai-agent-session-view/shell-plumbing-is-hidden-unless-verbose
  it("shows the wrapper shells only with verbose on", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    renderView();
    const firstCall = (await screen.findByText("ls /private/tmp | head -3")).closest("li");
    if (!firstCall) throw new Error("no group");
    expect(names(firstCall)).toEqual(["ls", "head"]);

    fireEvent.click(screen.getByRole("switch", { name: "Show shell plumbing" }));
    expect(names(firstCall)).toEqual(["zsh", "ls", "head"]);
  });

  it("collapses and expands a tool call", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    renderView();
    const header = (await screen.findByText("ls /private/tmp | head -3")).closest("button");
    if (!header) throw new Error("no header");
    expect(screen.getByRole("button", { name: "ls" })).toBeVisible();
    fireEvent.click(header);
    expect(header).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("button", { name: "ls" })).not.toBeInTheDocument();
  });

  // spec:web-ui/ai-agent-session-view-navigation/a-process-opens-its-detail-beside-the-session
  it("opens a selected process's detail beside the session, with its host graph and timeline", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    const detail = vi.spyOn(api, "getProcessDetail").mockImplementation(() => new Promise(() => undefined));
    vi.spyOn(api, "listAlertsByProcessId").mockResolvedValue([]);
    renderView();
    const ls = await screen.findByRole("button", { name: "ls" });
    expect(screen.queryByRole("heading", { name: "Process detail" })).not.toBeInTheDocument();
    fireEvent.click(ls);
    expect(ls).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("heading", { name: "Process detail" })).toBeVisible();
    expect(detail).toHaveBeenCalledWith("H1", 80728, expect.any(Number), undefined);
    // The fixture's ls forked at 101 ms and exited at 106 ms. The graph's window ends just after the fork, which selects it; the
    // timeline's ends just after the exit, so the process's own events are inside it.
    expect(screen.getByRole("link", { name: "Open in host graph" })).toHaveAttribute("href", "/hosts/H1?process=2298323&at=102");
    expect(screen.getByRole("link", { name: "Show in timeline" })).toHaveAttribute("href", "/hosts/H1?view=timeline&pid=80728&at=107");
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("heading", { name: "Process detail" })).not.toBeInTheDocument();
  });

  it("says when the session has more processes than were read", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ truncated: true, returned: 16, total_matched: 2500 }));
    renderView();
    expect(await screen.findByRole("status")).toHaveTextContent("Showing the first 16 of 2,500 processes in this session.");
  });

  // spec:web-ui/ai-agent-session-view-badges/the-header-reads-the-session-s-record
  it("reads the session's record for the header", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    // The record names the agent its markers reported most recently, which wins over what the processes carry.
    const latest = record({ agent_name: "claude", agent_version: "2.1.297" });
    const spy = vi.spyOn(api, "listAgentSessions").mockResolvedValue({ rows: [latest], total_matched: 1 });
    renderView();
    expect(await screen.findByText("agent pid 80673")).toBeVisible();
    expect(screen.getByRole("heading", { name: "claude 2.1.297" })).toBeVisible();
    expect(spy).toHaveBeenCalledWith({ host_id: "H1", session: SESSION });
    // The record's project wins over the first call's working directory.
    expect(screen.getByText("/Users/dev/project")).toBeVisible();
    expect(screen.queryByText("/private/tmp")).not.toBeInTheDocument();
  });

  // spec:web-ui/ai-agent-session-view-badges/retention-is-reported-when-the-session-began-before-it
  it.each([
    ["began before the retention cutoff", 60_000_000, true],
    ["began after it", 40_000_000, false],
  ])("reports retention only when the session %s", async (_name, retainedFrom, shown) => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ retained_from_ns: retainedFrom }));
    vi.spyOn(api, "listAgentSessions").mockResolvedValue({ rows: [record({ first_seen_ns: 50_000_000 })], total_matched: 1 });
    renderView();
    expect(await screen.findByText("agent pid 80673")).toBeVisible();
    expect(screen.queryByText(/removed by retention/) !== null).toBe(shown);
  });

  // spec:web-ui/ai-agent-session-view-badges/alerts-are-badged-where-they-were-raised
  it("badges an alert on its process and its tool call, linking to the alert", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    const spy = vi.spyOn(api, "listAlerts").mockResolvedValue([alert({ severity: "critical" })]);
    renderView();
    const link = await screen.findByRole("link", { name: "System discovery" });
    expect(link).toHaveAttribute("href", "/alerts/2047");
    // One past the cap, so a session with more alerts than are read is reported.
    expect(spy).toHaveBeenCalledWith({ host_id: "H1", agent_session: SESSION, limit: 1001 });
    const header = screen.getByText("ls /private/tmp | head -3").closest("button");
    if (!header) throw new Error("no header");
    expect(within(header).getByText("1 alert")).toHaveClass("badge--critical");
  });

  // spec:web-ui/ai-agent-session-view-badges/an-alerted-process-is-never-hidden-as-plumbing
  it("lists a wrapper shell an alert was raised on, with verbose off", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    vi.spyOn(api, "listAlerts").mockResolvedValue([alert({ process_id: 2298322 })]);
    renderView();
    const firstCall = (await screen.findByRole("link", { name: "System discovery" })).closest(".session-view__call");
    if (!(firstCall instanceof HTMLElement)) throw new Error("no group");
    expect(names(firstCall)).toEqual(["zsh", "ls", "head"]);
    expect(within(firstCall).getByRole("link", { name: "System discovery" }).closest("li")?.querySelector(".session-view__name")
      ?.textContent).toBe("zsh");
  });

  // spec:web-ui/ai-agent-session-view-badges/a-long-session-opens-on-its-alerts
  it("opens a long session with only the calls an alert was raised in expanded", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: manyCalls(11) }));
    vi.spyOn(api, "listAlerts").mockResolvedValue([alert({ process_id: 71 })]);
    renderView();
    await screen.findByRole("link", { name: "System discovery" });
    expect(screen.getAllByRole("button", { expanded: true }).map((b) => b.querySelector("code")?.textContent)).toEqual(["step 6"]);
    expect(screen.getAllByRole("button", { expanded: false })).toHaveLength(10);
  });

  it("opens a short session with every call expanded", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: manyCalls(10) }));
    renderView();
    await screen.findByText("step 9");
    expect(screen.getAllByRole("button", { expanded: true })).toHaveLength(10);
  });

  // spec:web-ui/ai-agent-session-view-badges/a-privilege-change-is-badged
  it("badges the process that became root, and not the root process it ran", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    // sudo is setuid, so its exec runs as root under the agent's uid-501 shell; the id it runs is root like sudo.
    const sudoCall = proc(10, 10, 100, "/bin/zsh", ["/bin/zsh", "-c", "eval 'sudo id'"], [
      proc(11, 11, 101, "/usr/bin/sudo", ["sudo", "id"], [proc(12, 12, 102, "/usr/bin/id", ["id"], [], { uid: 0 })], { uid: 0 }),
    ], { tool_call_group: 10, uid: 501 });
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [sudoCall] }));
    renderView();
    const badge = await screen.findByText("runs as root");
    expect(badge).toBeVisible();
    expect(screen.getAllByText("runs as root")).toHaveLength(1);
    expect(badge.closest("li")?.querySelector(".session-view__name")?.textContent).toBe("sudo");
  });

  it("says when the session has more alerts than were read", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    // The 1,000 most recent are on a process outside this tree, so none renders; the 1,001st, on ls, is past the cap.
    const alerts = Array.from({ length: 1000 }, (_, i) => alert({ id: i + 1, process_id: 1 }));
    alerts.push(alert({ id: 1001, title: "Past the cap" }));
    vi.spyOn(api, "listAlerts").mockResolvedValue(alerts);
    renderView();
    expect(await screen.findByText(/has more than 1,000 alerts; only the 1,000 most recent are badged/)).toBeVisible();
    expect(screen.queryByText("Past the cap")).not.toBeInTheDocument();
  });

  it("credits a rule's author beside its alert", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    vi.spyOn(api, "listAlerts").mockResolvedValue([alert({ origin: "SigmaHQ, by Alejandro Ortuno, oscd.community" })]);
    renderView();
    expect(await screen.findByText("SigmaHQ, by Alejandro Ortuno, oscd.community")).toBeVisible();
  });

  it("says so when the session's alerts could not be read, and still lists its processes", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    vi.spyOn(api, "listAlerts").mockRejectedValue(new Error("boom"));
    renderView();
    expect(await screen.findByText("This session's alerts could not be loaded, so none are shown.")).toBeVisible();
    expect(screen.getByText("ls /private/tmp | head -3")).toBeVisible();
  });

  it("names the agent from the processes when the session's record cannot be read", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    vi.spyOn(api, "listAgentSessions").mockRejectedValue(new Error("boom"));
    renderView();
    expect(await screen.findByRole("heading", { name: "claude-code 2.1.296" })).toBeVisible();
    expect(screen.getByText("/private/tmp")).toBeVisible();
  });

  // spec:web-ui/ai-agent-session-view-navigation/search-expands-to-what-it-finds
  it("expands a collapsed call to what a search finds, and says how much it found", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: manyCalls(11) }));
    renderView();
    await screen.findByText("step 7");
    expect(screen.queryByRole("button", { name: "echo" })).not.toBeInTheDocument();
    fireEvent.change(screen.getByRole("searchbox", { name: "Search this session" }), { target: { value: "echo 7" } });
    const header = screen.getByText("step 7").closest("button");
    if (!header) throw new Error("no header");
    expect(header).toHaveAttribute("aria-expanded", "true");
    expect(within(header).getByText("1 match")).toBeVisible();
    expect(screen.getAllByRole("button", { expanded: true })).toHaveLength(1);
    expect(screen.getByRole("button", { name: "echo" }).closest(".session-view__row")).toHaveClass("session-view__row--hit");
  });

  // spec:web-ui/ai-agent-session-view-navigation/a-long-list-shows-more-on-request
  it("lists the first 20 processes of a long list and the rest on request, past the cap for a search hit", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    const children = Array.from({ length: 25 }, (_, i) => proc(100 + i, 100 + i, 10 + i, "/usr/bin/wc", ["wc", `f${String(i)}`]));
    const call = proc(1, 1, 1, "/bin/zsh", ["/bin/zsh", "-c", "eval 'wc f*'"], children, { tool_call_group: 1 });
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [call] }));
    renderView();
    await screen.findByText("wc f0");
    expect(screen.getAllByRole("button", { name: "wc" })).toHaveLength(20);
    fireEvent.change(screen.getByRole("searchbox", { name: "Search this session" }), { target: { value: "wc f23" } });
    expect(screen.getByText("wc f23")).toBeVisible();
    expect(screen.getAllByRole("button", { name: "wc" })).toHaveLength(21);
    fireEvent.click(screen.getByRole("button", { name: "Show 4 more processes" }));
    expect(screen.getAllByRole("button", { name: "wc" })).toHaveLength(25);
    expect(screen.queryByRole("button", { name: /Show \d+ more/ })).not.toBeInTheDocument();
  });

  it("lists an alerted process past the cap, since the call opened to show it", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    const children = Array.from({ length: 25 }, (_, i) => proc(100 + i, 100 + i, 10 + i, "/usr/bin/wc", ["wc", `f${String(i)}`]));
    const call = proc(1, 1, 1, "/bin/zsh", ["/bin/zsh", "-c", "eval 'wc f*'"], children, { tool_call_group: 1 });
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [call] }));
    vi.spyOn(api, "listAlerts").mockResolvedValue([alert({ process_id: 123 })]);
    renderView();
    expect(await screen.findByRole("link", { name: "System discovery" })).toBeVisible();
    expect(screen.getByText("wc f23")).toBeVisible();
    expect(screen.getAllByRole("button", { name: "wc" })).toHaveLength(21);
  });

  it("does not fold a session that began before the retention cutoff", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    const children = Array.from({ length: 3 }, (_, i) => proc(100 + i, 100 + i, 10 + i, "/usr/bin/wc", ["wc", "-l", "f"]));
    const call = proc(1, 1, 1, "/bin/zsh", ["/bin/zsh", "-c", "eval 'loop'"], children, { tool_call_group: 1 });
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [call], retained_from_ns: 60_000_000 }));
    vi.spyOn(api, "listAgentSessions").mockResolvedValue({ rows: [record({ first_seen_ns: 50_000_000 })], total_matched: 1 });
    renderView();
    expect(await screen.findByText(/removed by retention/)).toBeVisible();
    expect(screen.getAllByRole("button", { name: "wc" })).toHaveLength(3);
  });

  it("does not fold a truncated session's processes", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    const children = Array.from({ length: 3 }, (_, i) => proc(100 + i, 100 + i, 10 + i, "/usr/bin/wc", ["wc", "-l", "f"]));
    const call = proc(1, 1, 1, "/bin/zsh", ["/bin/zsh", "-c", "eval 'loop'"], children, { tool_call_group: 1 });
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [call], truncated: true, total_matched: 5000 }));
    renderView();
    await screen.findByRole("status");
    expect(screen.getAllByRole("button", { name: "wc" })).toHaveLength(3);
  });

  // spec:web-ui/ai-agent-session-view-navigation/identical-processes-are-folded
  it("shows identical processes as one row with their count and time span", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    const children = Array.from({ length: 3 }, (_, i) =>
      proc(100 + i, 100 + i, 10 + i, "/usr/bin/wc", ["wc", "-l", "f"], [], { exit_code: 0 }));
    const call = proc(1, 1, 1, "/bin/zsh", ["/bin/zsh", "-c", "eval 'loop'"], children, { tool_call_group: 1 });
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [call] }));
    renderView();
    const wc = await screen.findByRole("button", { name: "wc" });
    const row = wc.closest(".session-view__row");
    if (!(row instanceof HTMLElement)) throw new Error("no row");
    expect(within(row).getByText("×3")).toBeVisible();
    expect(row).toHaveTextContent(/to/);
    // They all exited 0, so the folded row says so.
    expect(row).toHaveTextContent(/exit 0/);
    expect(screen.getAllByRole("button", { name: "wc" })).toHaveLength(1);
  });

  // spec:web-ui/activity-tabs/a-session-s-network-tab-lists-every-destination-with-its-process
  it("switches to the session's activity, and opens the detail of a process named there", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    vi.spyOn(api, "getProcessDetail").mockImplementation(() => new Promise(() => undefined));
    vi.spyOn(api, "listAlertsByProcessId").mockResolvedValue([]);
    const activity = vi.spyOn(api, "getActivity").mockResolvedValue(lsActivity);
    renderView();
    await screen.findByText("ls /private/tmp | head -3");
    expect(activity).not.toHaveBeenCalledWith("H1", { kind: "session", session: SESSION });
    fireEvent.click(screen.getByRole("button", { name: "Activity" }));
    expect(await screen.findByText("1 connection to 1 destination")).toBeVisible();
    expect(activity).toHaveBeenCalledWith("H1", { kind: "session", session: SESSION });
    expect(screen.queryByText("ls /private/tmp | head -3")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "ls (80728)" }));
    expect(screen.getByRole("heading", { name: "Process detail" })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Commands" }));
    expect(screen.getByText("ls /private/tmp | head -3")).toBeVisible();
  });

  // spec:web-ui/session-processes-view/every-process-is-listed-under-the-agent-that-ran-it
  // spec:web-ui/session-processes-view/a-reparented-process-stays-under-its-creator
  // The agent's own processes (issue #1361): counted, hidden until asked for, then listed under the agent marked as its own.
  // spec:web-ui/agent-own-processes-view/the-agent-s-own-processes-are-counted-and-listed-on-request
  it("counts the agent's own processes in the Processes view and lists them, marked, on request", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    const scan = proc(20, 20, 50, "/opt/homebrew/bin/rg", ["rg", "--files", "--hidden"], [], { agent_session_id: undefined });
    const snapshot = proc(21, 21, 60, "/bin/zsh", ["/bin/zsh", "-c", "-l", "SNAPSHOT_FILE=s"], [
      proc(22, 22, 61, "/usr/bin/env", ["env"], [], { agent_session_id: undefined }),
    ], { agent_session_id: undefined });
    const agent = proc(9, 5000, 0, "/Users/victor/.local/share/claude/versions/2.1.302", ["claude"], [scan, snapshot],
      { agent_session_id: undefined });
    const call = proc(10, 10, 100, "/bin/zsh", ["/bin/zsh", "-c", "eval 'ls'"], [], { tool_call_group: 10, ppid: 5000, parent_process_id: 9 });
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [call], agents: [agent] }));
    renderView();
    fireEvent.click(await screen.findByRole("button", { name: "Processes" }));
    const names = () => [...document.querySelectorAll(".session-view__processes .session-view__name")].map((b) => b.textContent);
    expect(names()).toEqual(["claude", "zsh"]);
    expect(screen.queryByText("agent's own")).toBeNull();
    const toggle = screen.getByLabelText("Show the agent's own processes (3)");
    expect(toggle).toBeVisible();

    fireEvent.click(toggle);
    expect(names()).toEqual(["claude", "rg", "zsh", "env", "zsh"]);
    expect(screen.getAllByText("agent's own")).toHaveLength(3);
    const commandRow = [...document.querySelectorAll(".session-view__processes li")].find((li) =>
      li.querySelector(".session-view__cmdline")?.textContent.includes("eval"));
    expect(commandRow?.querySelector(".session-view__row")?.textContent).not.toContain("agent's own");
  });

  // An alert on one of the agent's own processes is read by the agent (the session read covers stamped processes only) and badged.
  // spec:server-rest-api/agent-own-processes/an-agent-s-own-processes-alerts-are-read-by-the-agent
  it("badges an alert on one of the agent's own processes", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    const keychain = proc(20, 20, 50, "/usr/bin/security", ["security", "find-generic-password", "-s", "Claude Code-credentials"], [],
      { agent_session_id: undefined });
    const agent = proc(9, 5000, 0, "/Users/victor/.local/share/claude/versions/2.1.302", ["claude"], [keychain],
      { agent_session_id: undefined });
    const call = proc(10, 10, 100, "/bin/zsh", ["/bin/zsh", "-c", "eval 'ls'"], [], { tool_call_group: 10, ppid: 5000, parent_process_id: 9 });
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [call], agents: [agent] }));
    const read = vi.spyOn(api, "listAlerts").mockImplementation((params) =>
      Promise.resolve(params?.agent_process === 9 ? [alert({ id: 7, process_id: 20, title: "Keychain credential read" })] : []));
    renderView();
    fireEvent.click(await screen.findByRole("button", { name: "Processes" }));
    fireEvent.click(screen.getByLabelText("Show the agent's own processes (1)"));
    const badge = await screen.findByText("Keychain credential read");
    expect(badge).toBeVisible();
    expect(badge.closest("li")?.querySelector(".session-view__name")?.textContent).toBe("security");
    expect(read).toHaveBeenCalledWith(expect.objectContaining({ host_id: "H1", agent_process: 9, served_session: SESSION }));
  });

  it("offers no agent's own processes toggle when the agent ran none", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    const agent = proc(9, 5000, 0, "/Users/victor/.local/share/claude/versions/2.1.302", ["claude"], [], { agent_session_id: undefined });
    const call = proc(10, 10, 100, "/bin/zsh", ["/bin/zsh", "-c", "eval 'ls'"], [], { tool_call_group: 10, ppid: 5000, parent_process_id: 9 });
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [call], agents: [agent] }));
    renderView();
    fireEvent.click(await screen.findByRole("button", { name: "Processes" }));
    expect(await screen.findByText("2 processes, under the agent that ran them")).toBeVisible();
    expect(screen.queryByText(/agent's own processes/)).toBeNull();
  });

  it("lists every process under the agent in the Processes view, a reparented one marked", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getProcessDetail").mockImplementation(() => new Promise(() => undefined));
    vi.spyOn(api, "listAlertsByProcessId").mockResolvedValue([]);
    const agent = proc(9, 5000, 0, "/Users/victor/.local/share/claude/versions/2.1.296", ["claude"], [], { agent_session_id: undefined });
    // A double fork: the subshell's copy of zsh exits before its child execs sleep, which then reports launchd as its parent.
    const daemon = proc(12, 12, 102, "/bin/sleep", ["sleep", "47"], [], { ppid: 1, reparented: true });
    const call = proc(10, 10, 100, "/bin/zsh", ["/bin/zsh", "-c", "eval '(sleep 47 &)'"], [proc(11, 11, 101, "/bin/zsh", undefined, [daemon])],
      { tool_call_group: 10, ppid: 5000, parent_process_id: 9 });
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [call], agents: [agent] }));
    renderView();
    expect(await screen.findByText("(sleep 47 &)", { selector: "code" })).toBeVisible();
    expect(screen.getByText("Show shell plumbing")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Processes" }));
    expect(screen.getByRole("button", { name: "Processes", pressed: true })).toBeVisible();
    expect(screen.getByText("4 processes, under the agent that ran them")).toBeVisible();
    // Hidden but kept in place, so the header wraps as it does in Commands and the view switcher stays where it was.
    // spec:web-ui/stable-session-view-switcher/the-plumbing-toggle-is-hidden-not-removed-outside-commands
    expect(screen.getByText("Show shell plumbing")).not.toBeVisible();
    // The agent leads, its command's wrapper and the subshell's copy of zsh are listed, and the daemon is under the copy that made it.
    const names = [...document.querySelectorAll(".session-view__processes .session-view__name")].map((b) => b.textContent);
    expect(names).toEqual(["claude", "zsh", "zsh", "sleep"]);
    expect(screen.getByText("agent")).toBeVisible();
    const reparented = screen.getByText("reparented, ppid 1");
    expect(reparented.closest("li")?.querySelector(".session-view__name")?.textContent).toBe("sleep");
    expect(reparented.parentElement).toHaveAttribute("title", expect.stringContaining("its parent is now pid 1"));
    // Only the adopted process is marked: its creators are not.
    expect(screen.getAllByText("reparented, ppid 1")).toHaveLength(1);

    fireEvent.change(screen.getByLabelText("Search this session"), { target: { value: "sleep 47" } });
    expect(screen.getByPlaceholderText("Search processes")).toBeVisible();
    expect(document.querySelectorAll(".session-view__processes .session-view__row--hit")).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "claude" }));
    expect(screen.getByRole("heading", { name: "Process detail" })).toBeVisible();
  });

  it("opens the agent's detail from the session's activity", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getProcessDetail").mockImplementation(() => new Promise(() => undefined));
    vi.spyOn(api, "listAlertsByProcessId").mockResolvedValue([]);
    const agent = proc(9, 5000, 0, "/Users/victor/.local/share/claude/versions/2.1.296", ["claude"], [], { agent_session_id: undefined });
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ agents: [agent] }));
    vi.spyOn(api, "getActivity").mockResolvedValue({
      ...lsActivity,
      network: { events: 0, distinct: 0, truncated: false, rows: [] },
      files: {
        events: 1, distinct: 1, truncated: false,
        rows: [{ pid: 5000, pidversion: 1, count: 1, first_ns: 1, last_ns: 1, operation: "modify", path: "/Users/dev/project/main.go" }],
      },
      processes: [{ id: 9, pid: 5000, pidversion: 1, path: "/Users/victor/.local/share/claude/versions/2.1.296" }],
    });
    renderView();
    await screen.findByText("ls /private/tmp | head -3");
    fireEvent.click(screen.getByRole("button", { name: "Activity" }));
    fireEvent.click(await screen.findByRole("button", { name: /^Files/ }));
    fireEvent.click(await screen.findByRole("button", { name: "claude (5000)" }));
    expect(screen.getByRole("heading", { name: "Process detail" })).toBeVisible();
  });

  it("says 1 process, not 1 processes, for a session of one", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [proc(10, 10, 100, "/bin/zsh", ["/bin/zsh", "-c", "eval 'pwd'"])] }));
    renderView();
    expect(await screen.findByText("1 process", { selector: "span" })).toBeVisible();
  });

  it("says how many roots sit beside the agent when their creator was not read", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    const agent = proc(9, 5000, 0, "/Users/victor/.local/share/claude/versions/2.1.296", ["claude"], [], { agent_session_id: undefined });
    const [stray, ...created] = realSession();
    const roots = [stray, ...created.map((r) => ({ ...r, parent_process_id: 9 }))];
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots, agents: [agent] }));
    renderView();
    await screen.findByText("ls /private/tmp | head -3");
    fireEvent.click(screen.getByRole("button", { name: "Processes" }));
    expect(screen.getByText("17 processes. 1 root sits beside the agent: the process that created it was not read")).toBeVisible();
  });

  it("lists the commands as roots when the agent process was not seen", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    renderView();
    await screen.findByText("ls /private/tmp | head -3");
    fireEvent.click(screen.getByRole("button", { name: "Processes" }));
    expect(screen.getByText(/16 processes\. The agent process was not seen/)).toBeVisible();
  });

  // spec:web-ui/inferred-launches-in-the-ui/a-session-lists-a-launch-under-the-call-that-asked
  it("lists what launchd started for a call's open under that call, marked as inferred", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    // As captured on edr-dev: the call's open, and TextEdit, a root launchd started that carries the session's markers.
    const call = proc(10, 10, 100, "/bin/zsh", ["/bin/zsh", "-c", "eval 'open -a TextEdit'"], [
      proc(11, 11, 101, "/usr/bin/open", ["open", "-a", "TextEdit"]),
    ], { tool_call_group: 10 });
    const textEdit = proc(12, 12, 102, "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit", ["TextEdit"]);
    const links = [{ from: 11, to: 12, kind: "inferred_launch" as const }];
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [call, textEdit], links }));
    renderView();
    expect(await screen.findByText("open -a TextEdit", { selector: "code" })).toBeVisible();
    expect(callHeaders()).toHaveLength(1);
    const badge = screen.getByText("inferred launch");
    expect(badge.closest("li")?.querySelector(".session-view__name")?.textContent).toBe("TextEdit");
    // TextEdit sits under the open that asked for it.
    expect(badge.closest("li")?.parentElement?.closest("li")?.querySelector(".session-view__name")?.textContent).toBe("open");
  });

  // spec:web-ui/services-under-their-app/a-service-hangs-under-the-app-responsible-for-it
  it("lists an app's service under the app, badged as a service", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    const call = proc(10, 10, 100, "/bin/zsh", ["/bin/zsh", "-c", "eval 'open -a TextEdit'"], [
      proc(11, 11, 101, "/usr/bin/open", ["open", "-a", "TextEdit"]),
    ], { tool_call_group: 10 });
    const textEdit = proc(12, 12, 102, "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit", ["TextEdit"]);
    const service = proc(13, 13, 103, "/System/Library/PrivateFrameworks/X.framework/nsattributedstringagent", ["nsattributedstringagent"], [],
      { agent_session_id: undefined });
    const links = [{ from: 11, to: 12, kind: "inferred_launch" as const }, { from: 12, to: 13, kind: "responsible_process" as const }];
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [call, textEdit, service], links }));
    renderView();
    const badge = await screen.findByText("service");
    expect(badge).toBeVisible();
    expect(badge.closest("li")?.querySelector(".session-view__name")?.textContent).toBe("nsattributedstringagent");
    expect(badge.closest("li")?.parentElement?.closest("li")?.querySelector(".session-view__name")?.textContent).toBe("TextEdit");
    expect(badge.parentElement).toHaveAttribute("title", expect.stringContaining("responsible"));
  });

  it("lists a launch as a call of its own when the read carries no link for it", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    const call = proc(10, 10, 100, "/bin/zsh", ["/bin/zsh", "-c", "eval 'open -a TextEdit'"], [
      proc(11, 11, 101, "/usr/bin/open", ["open", "-a", "TextEdit"]),
    ], { tool_call_group: 10 });
    const textEdit = proc(12, 12, 102, "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit", ["TextEdit"]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ roots: [call, textEdit] }));
    renderView();
    await screen.findByText("open -a TextEdit", { selector: "code" });
    expect(callHeaders()).toHaveLength(2);
    expect(screen.queryByText("inferred launch")).not.toBeInTheDocument();
  });

  it("says how many processes there are at least when the server capped its count", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree({ truncated: true, total_matched: 10_000, total_matched_capped: true }));
    renderView();
    expect(await screen.findByRole("status")).toHaveTextContent("Showing the first 16 of more than 10,000 processes in this session.");
  });

  it("does not show the previous session's processes while the next session loads", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree")
      .mockResolvedValueOnce(tree())
      .mockImplementationOnce(() => new Promise(() => undefined));
    render(
      <MemoryRouter initialEntries={[`/agent-sessions/H1/${SESSION}`]}>
        <Link to="/agent-sessions/H1/other-session">next</Link>
        <Routes>
          <Route path="/agent-sessions/:hostId/:sessionId" element={<SessionView />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByText("ls /private/tmp | head -3")).toBeVisible();
    fireEvent.click(screen.getByRole("link", { name: "next" }));
    expect(await screen.findByText("Loading...")).toBeVisible();
    expect(screen.queryByText("ls /private/tmp | head -3")).not.toBeInTheDocument();
  });

  it("closes a process's detail when moving to another session", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockResolvedValue(tree());
    vi.spyOn(api, "getProcessDetail").mockImplementation(() => new Promise(() => undefined));
    vi.spyOn(api, "listAlertsByProcessId").mockResolvedValue([]);
    render(
      <MemoryRouter initialEntries={[`/agent-sessions/H1/${SESSION}`]}>
        <Link to="/agent-sessions/H1/other-session">next</Link>
        <Routes>
          <Route path="/agent-sessions/:hostId/:sessionId" element={<SessionView />} />
        </Routes>
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole("button", { name: "ls" }));
    expect(screen.getByRole("heading", { name: "Process detail" })).toBeVisible();
    fireEvent.click(screen.getByRole("link", { name: "next" }));
    expect(await screen.findByRole("button", { name: "ls" })).toBeVisible();
    expect(screen.queryByRole("heading", { name: "Process detail" })).not.toBeInTheDocument();
  });

  it("does not show the previous session's error after moving to another session", async () => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    let resolveNext: (t: TreeResponse) => void = () => undefined;
    vi.spyOn(api, "getSessionTree")
      .mockRejectedValueOnce(new Error("boom"))
      .mockImplementationOnce(() => new Promise((resolve) => { resolveNext = resolve; }));
    render(
      <MemoryRouter initialEntries={[`/agent-sessions/H1/${SESSION}`]}>
        <Link to="/agent-sessions/H1/other-session">next</Link>
        <Routes>
          <Route path="/agent-sessions/:hostId/:sessionId" element={<SessionView />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByText("Error: boom")).toBeVisible();
    fireEvent.click(screen.getByRole("link", { name: "next" }));
    expect(await screen.findByText("Loading...")).toBeVisible();
    expect(screen.queryByText("Error: boom")).not.toBeInTheDocument();
    resolveNext(tree());
    expect(await screen.findByText("ls /private/tmp | head -3")).toBeVisible();
  });

  it.each([
    [
      "an empty session",
      () => Promise.resolve(tree({ roots: [], returned: 0, total_matched: 0 })),
      "No processes are recorded for this session.",
    ],
    ["a failed read", () => Promise.reject(new Error("boom")), "Error: boom"],
  ])("states %s", async (_name, read, message) => {
    vi.spyOn(api, "listHosts").mockResolvedValue([]);
    vi.spyOn(api, "getSessionTree").mockImplementation(read);
    renderView();
    expect(await screen.findByText(message)).toBeVisible();
    expect(screen.getByRole("heading", { name: "Agent session" })).toBeVisible();
  });
});
