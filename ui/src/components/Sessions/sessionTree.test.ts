import { describe, it, expect } from "vitest";

import {
  buildCommands,
  buildProcessForest,
  countOwn,
  containsHit,
  countRows,
  forkSpan,
  searchCommands,
  searchRows,
  summarizeSession,
  type RowShape,
  type SessionRow,
} from "./sessionTree";
import type { ProcessNode } from "../../types";
import { MS, proc, realSession } from "../../test/agentSession";

const QUIET: RowShape = { verbose: false };
const VERBOSE: RowShape = { verbose: true };

// outline renders rows as indented "path" lines, so a test reads the shape the view shows.
function outline(rows: SessionRow[], depth = 0): string[] {
  return rows.flatMap((r) => [`${"  ".repeat(depth)}${r.node.path}`, ...outline(r.children, depth + 1)]);
}

describe("buildCommands", () => {
  // spec:web-ui/ai-agent-session-view/tool-calls-are-labelled-with-the-command-the-agent-ran
  it("makes one group per tool call, in the order they ran, labelled with the agent's command", () => {
    const calls = buildCommands(realSession(), QUIET);
    expect(calls.map((c) => c.command)).toEqual([
      "ls /private/tmp | head -3",
      "(sleep 47 &)",
      "nohup sleep 48 >/dev/null 2>&1 &",
      "env -i /bin/echo qa1280",
      `/bin/sh -c "sleep 1; echo qa1280-done"`,
    ]);
    expect(calls.map((c) => c.key)).toEqual(["row:2298322", "row:2298325", "row:2298439", "row:2298442", "row:2298447"]);
  });

  // spec:web-ui/ai-agent-session-view/a-daemon-the-agent-started-stays-in-its-tool-call
  it("keeps a backgrounded daemon inside the call that started it and hides the subshell copy that started it", () => {
    const [, subshell] = buildCommands(realSession(), QUIET);
    expect(outline(subshell.rows)).toEqual(["/bin/sleep"]);
    // The daemon outlived the call, and the group's span reaches its exit.
    const nohup = buildCommands(realSession(), QUIET)[2];
    expect(outline(nohup.rows)).toEqual(["/usr/bin/nohup", "/bin/sleep"]);
    expect(nohup.lastNs).toBe(350_000 * MS);
  });

  // spec:web-ui/ai-agent-session-view/shell-plumbing-is-hidden-unless-verbose
  it("lists the wrapper shell and the subshell copy only when verbose", () => {
    const quiet = buildCommands(realSession(), QUIET);
    expect(outline(quiet[0].rows)).toEqual(["/bin/ls", "/usr/bin/head"]);
    expect(quiet[1].processCount).toBe(3);

    const verbose = buildCommands(realSession(), VERBOSE);
    expect(outline(verbose[0].rows)).toEqual(["/bin/zsh", "  /bin/ls", "  /usr/bin/head"]);
    expect(outline(verbose[1].rows)).toEqual(["/bin/zsh", "  /bin/zsh", "    /bin/sleep"]);
    expect(verbose.map((c) => c.command)).toEqual(quiet.map((c) => c.command));
  });

  it("does not stretch a call's span to an exit the server synthesized", () => {
    const daemon = proc(3, 3, 202, "/bin/sleep", ["sleep", "47"], [], { exit_reason: "ttl_reconciliation", exit_time_ns: 9_000_000 * MS });
    const root = proc(2, 2, 200, "/bin/zsh", ["zsh", "-c", "eval '(sleep 47 &)'"], [daemon], { tool_call_group: 2 });
    // The shell's observed exit is the call's last activity, not the sweep that closed the sleep hours later.
    expect(buildCommands([root], QUIET)[0].lastNs).toBe(205 * MS);
  });

  // spec:web-ui/ai-agent-session-view-badges/an-alerted-process-is-never-hidden-as-plumbing
  it("lists plumbing an alert was raised on, even with verbose off", () => {
    const keep = new Set([2298322, 2298326]);
    const calls = buildCommands(realSession(), { verbose: false, keep });
    expect(outline(calls[0].rows)).toEqual(["/bin/zsh", "  /bin/ls", "  /usr/bin/head"]);
    expect(outline(calls[1].rows)).toEqual(["/bin/zsh", "  /bin/sleep"]);
  });

  // spec:web-ui/ai-agent-session-view-badges/a-privilege-change-is-badged
  it("marks a process that runs as a different user from its creator", () => {
    const root = proc(2, 2, 200, "/bin/zsh", ["/bin/zsh", "-c", "eval 'sudo id'"], [
      proc(3, 3, 201, "/usr/bin/sudo", ["sudo", "id"], [proc(4, 4, 202, "/usr/bin/id", ["id"], [], { uid: 0 })], { uid: 0 }),
    ], { tool_call_group: 2, uid: 501 });
    const [call] = buildCommands([root], QUIET);
    const [sudo] = call.rows;
    expect(sudo.uidChange).toEqual({ from: 501, to: 0 });
    expect(sudo.children[0].uidChange).toBeUndefined();
  });

  it("hides a shell copy that reports no user, as forks do, and compares what it runs with the shell's user", () => {
    // As captured: the subshell's fork of zsh carries no uid. A root process under it is still a change from the shell's uid 501.
    const copy = proc(3, 3, 201, "/bin/zsh", undefined, [proc(4, 4, 202, "/bin/sleep", ["sleep", "1"], [], { uid: 0 })]);
    const root = proc(2, 2, 200, "/bin/zsh", ["/bin/zsh", "-c", "eval '(sleep 1 &)'"], [copy], { tool_call_group: 2, uid: 501 });
    const [call] = buildCommands([root], QUIET);
    expect(outline(call.rows)).toEqual(["/bin/sleep"]);
    expect(call.rows[0].uidChange).toEqual({ from: 501, to: 0 });
  });

  it("compares what a listed shell copy runs with the user the copy inherited", () => {
    // Verbose lists the copy, which reports no user; the root sleep under it is still a change from the shell's uid 501.
    const copy = proc(3, 3, 201, "/bin/zsh", undefined, [proc(4, 4, 202, "/bin/sleep", ["sleep", "1"], [], { uid: 0 })]);
    const root = proc(2, 2, 200, "/bin/zsh", ["/bin/zsh", "-c", "eval '(sleep 1 &)'"], [copy], { tool_call_group: 2, uid: 501 });
    const [shell] = buildCommands([root], VERBOSE)[0].rows;
    expect(shell.children[0].uidChange).toBeUndefined();
    expect(shell.children[0].children[0].uidChange).toEqual({ from: 501, to: 0 });
  });

  it("lists a shell copy that runs as another user, since that is a privilege change", () => {
    const copy = proc(3, 3, 201, "/bin/zsh", undefined, [proc(4, 4, 202, "/bin/sleep", ["sleep", "1"], [], { uid: 0 })], { uid: 0 });
    const root = proc(2, 2, 200, "/bin/zsh", ["/bin/zsh", "-c", "eval '(sleep 1 &)'"], [copy], { tool_call_group: 2, uid: 501 });
    const [call] = buildCommands([root], QUIET);
    expect(outline(call.rows)).toEqual(["/bin/zsh", "  /bin/sleep"]);
    expect(call.rows[0].uidChange).toEqual({ from: 501, to: 0 });
  });

  it("compares a hoisted process with its real creator, not the row it is listed under", () => {
    // The shell copy is hidden, so the sleep is listed under the call; its creator is still the copy, which ran as root.
    const copy = proc(3, 3, 201, "/bin/zsh", undefined, [proc(4, 4, 202, "/bin/sleep", ["sleep", "1"], [], { uid: 0 })], { uid: 0 });
    const root = proc(2, 2, 200, "/bin/zsh", ["/bin/zsh", "-c", "eval '(sleep 1 &)'"], [copy], { tool_call_group: 2, uid: 0 });
    expect(buildCommands([root], QUIET)[0].rows[0].uidChange).toBeUndefined();
  });

  it("collects every process of a call, hidden plumbing included", () => {
    expect(buildCommands(realSession(), QUIET)[1].processIds).toEqual([2298325, 2298326, 2298327]);
  });

  it("keeps a fork that never exec'd when it is not a shell copy", () => {
    const worker = proc(11, 2, 11, "/usr/bin/python3", undefined);
    const root = proc(10, 1, 10, "/usr/bin/python3", ["python3", "serve.py"], [worker], { tool_call_group: 1 });
    const [call] = buildCommands([root], QUIET);
    expect(call.command).toBe("python3 serve.py");
    expect(outline(call.rows)).toEqual(["/usr/bin/python3", "  /usr/bin/python3"]);
  });

  it("keeps a fork that never exec'd when it is a different shell from its creator", () => {
    const fork = proc(11, 2, 11, "/bin/bash", undefined);
    const root = proc(10, 1, 10, "/bin/zsh", ["/bin/zsh", "-c", "eval 'bash -c x'"], [fork], { tool_call_group: 1 });
    expect(outline(buildCommands([root], QUIET)[0].rows)).toEqual(["/bin/bash"]);
  });

  it("folds a root whose creator was not read into its tool call's group", () => {
    const orphan = proc(9, 9, 150, "/usr/bin/git", ["git", "status"], [], { tool_call_group: 80727 });
    const calls = buildCommands([...realSession(), orphan], QUIET);
    expect(calls).toHaveLength(5);
    expect(outline(calls[0].rows)).toEqual(["/bin/ls", "/usr/bin/head", "/usr/bin/git"]);
    expect(calls[0].processCount).toBe(4);
  });

  it("starts a new group when a later call's leader reuses an earlier call's process group", () => {
    const first = proc(1, 700, 100, "/bin/zsh", ["/bin/zsh", "-c", "eval 'git status'"], [], { tool_call_group: 700 });
    const reused = proc(2, 700, 900, "/bin/zsh", ["/bin/zsh", "-c", "eval 'make test'"], [], { tool_call_group: 700 });
    // A process of the later call whose creator was not read joins the later call, not the earlier one.
    const orphan = proc(3, 701, 950, "/usr/bin/make", ["make", "test"], [], { tool_call_group: 700 });
    const calls = buildCommands([orphan, reused, first], QUIET);
    expect(calls.map((c) => c.command)).toEqual(["git status", "make test"]);
    expect(outline(calls[1].rows)).toEqual(["/usr/bin/make"]);
  });

  it("gives a root without a tool-call group a group of its own, labelled with its command line", () => {
    const hook = proc(7, 7, 50, "/usr/bin/osascript", ["osascript", "-e", "beep"]);
    const [first] = buildCommands([hook, ...realSession()], QUIET);
    expect(first.key).toBe("row:7");
    expect(first.command).toBe("osascript -e beep");
    expect(outline(first.rows)).toEqual(["/usr/bin/osascript"]);
  });
});

describe("summarizeSession", () => {
  it("names the agent, the first call's project, the span and every process", () => {
    expect(summarizeSession(realSession())).toEqual({
      agentName: "claude-code",
      agentVersion: "2.1.296",
      project: "/private/tmp",
      firstNs: 100 * MS,
      lastNs: 350_000 * MS,
      processCount: 16, // the capture's 16, as the sessions list counts them
    });
  });

  it("takes the project from the call that ran first, whatever order the forest arrives in", () => {
    const later = proc(2, 2, 200, "/bin/zsh", ["zsh"], [], { cwd: "/Users/dev/other" });
    const earlier = proc(1, 1, 100, "/bin/zsh", ["zsh"], [], { cwd: "/Users/dev/project" });
    expect(summarizeSession([later, earlier]).project).toBe("/Users/dev/project");
  });

  it("is empty for an empty session", () => {
    expect(summarizeSession([])).toEqual({ processCount: 0 });
  });
});

// loop is one tool call, `for f in ...; do wc -l $f; done`, that ran wc n times and then sort once, as children of its shell.
function loop(n: number, over: (i: number) => Partial<ProcessNode> = () => ({})): ProcessNode {
  const wcs = Array.from({ length: n }, (_, i) => proc(100 + i, 100 + i, 10 + i, "/usr/bin/wc", ["wc", "-l", "f"], [], over(i)));
  const sort = proc(99, 99, 10 + n, "/usr/bin/sort", ["sort"]);
  return proc(1, 1, 1, "/bin/zsh", ["/bin/zsh", "-c", "eval 'for f in *; do wc -l f; done | sort'"], [...wcs, sort], {
    tool_call_group: 1,
  });
}

describe("folding", () => {
  // spec:web-ui/ai-agent-session-view-navigation/identical-processes-are-folded
  it("folds identical processes into one row that keeps the others, in order", () => {
    const [call] = buildCommands([loop(5)], QUIET);
    expect(outline(call.rows)).toEqual(["/usr/bin/wc", "/usr/bin/sort"]);
    expect(call.rows[0].node.id).toBe(100);
    expect(call.rows[0].folded?.map((n) => n.id)).toEqual([101, 102, 103, 104]);
    expect(call.rows[1].folded).toBeUndefined();
    expect(call.processCount).toBe(7);
  });

  it("does not fold a process that was flagged, changed privilege, or started anything", () => {
    const keep = new Set([102]);
    const tree = loop(5, (i) => {
      if (i === 3) return { uid: 0 };
      if (i === 4) return { children: [proc(200, 200, 30, "/bin/cat", ["cat"])] };
      return {};
    });
    tree.uid = 501;
    const [call] = buildCommands([tree], { verbose: false, keep });
    expect(outline(call.rows)).toEqual(["/usr/bin/wc", "/usr/bin/wc", "/usr/bin/wc", "/usr/bin/wc", "  /bin/cat", "/usr/bin/sort"]);
    expect(call.rows[0].folded?.map((n) => n.id)).toEqual([101]);
  });

  it("folds identical processes at every level, and merges a folded run hoisted from a shell copy into its siblings", () => {
    // The call's shell ran wc twice itself and twice more from a subshell, whose copy of the shell is hidden: one row of four.
    const wc = (id: number, at: number) => proc(id, id, at, "/usr/bin/wc", ["wc", "-l", "f"]);
    // The subshell started at 20 but its wcs ran at 100 and 101, after the direct wc at 40.
    const copy = proc(20, 20, 20, "/bin/zsh", undefined, [wc(21, 100), wc(22, 101)]);
    // A pipeline the call ran nests three identical cats under xargs.
    const xargs = proc(30, 30, 30, "/usr/bin/xargs", ["xargs", "cat"], [proc(31, 31, 31, "/bin/cat", ["cat", "f"]),
      proc(32, 32, 32, "/bin/cat", ["cat", "f"]), proc(33, 33, 33, "/bin/cat", ["cat", "f"])]);
    const root = proc(1, 1, 1, "/bin/zsh", ["/bin/zsh", "-c", "eval 'x'"], [wc(10, 10), copy, wc(11, 40), xargs], { tool_call_group: 1 });
    const [call] = buildCommands([root], QUIET);
    expect(outline(call.rows)).toEqual(["/usr/bin/wc", "/usr/bin/xargs", "  /bin/cat"]);
    expect(call.rows[0].folded?.map((n) => n.id)).toEqual([21, 22, 11]);
    // Hoisting put the subshell's run (100, 101) ahead of the direct wc at 40, so the span is read across all of them, not from the last.
    expect(forkSpan(call.rows[0])).toEqual({ firstNs: 10 * MS, lastNs: 101 * MS });
    expect(call.rows[1].children[0].folded?.map((n) => n.id)).toEqual([32, 33]);
  });

  // spec:web-ui/ai-agent-session-view-navigation/runs-that-ended-differently-are-not-folded-together
  it("keeps runs that ended differently apart, so a failure is not hidden behind a success", () => {
    const [call] = buildCommands([loop(4, (i) => ({ exit_reason: "event", exit_code: i === 2 ? 1 : 0 }))], QUIET);
    const wcs = call.rows.filter((r) => r.node.path === "/usr/bin/wc");
    expect(wcs.map((r) => [r.node.exit_code, 1 + (r.folded?.length ?? 0)])).toEqual([[0, 3], [1, 1]]);
  });

  // spec:web-ui/ai-agent-session-view-navigation/nothing-is-folded-when-the-read-is-incomplete
  it("does not fold when the read left processes or alerts out", () => {
    const [call] = buildCommands([loop(5)], { verbose: false, incomplete: true });
    expect(call.rows.filter((r) => r.node.path === "/usr/bin/wc")).toHaveLength(5);
    expect(call.rows.some((r) => r.folded)).toBe(false);
  });

  it("draws no privilege change across an inferred launch, whose launcher is not its creator", () => {
    // A uid-501 open asked, and launchd started the app as root: that is launchd's doing, not a privilege change by the open.
    const app = proc(12, 12, 12, "/Applications/Helper.app/Contents/MacOS/Helper", ["Helper"], [], { uid: 0 });
    const open = proc(11, 11, 11, "/usr/bin/open", ["open", "-a", "Helper"], [app], { uid: 501 });
    const root = proc(10, 10, 10, "/bin/zsh", ["/bin/zsh", "-c", "eval 'open -a Helper'"], [open], { tool_call_group: 10, uid: 501 });
    const [call] = buildCommands([root], { verbose: false, inferred: new Set([12]) });
    const launched = call.rows[0].children[0];
    expect(launched.inferred).toBe(true);
    expect(launched.uidChange).toBeUndefined();
  });

  it("marks an inferred launch and never folds it with an identical sibling", () => {
    const tree = loop(3);
    const [call] = buildCommands([tree], { verbose: false, inferred: new Set([101]) });
    const wcs = call.rows.filter((r) => r.node.path === "/usr/bin/wc");
    expect(wcs.map((r) => [r.node.id, r.inferred ?? false, r.folded?.length ?? 0])).toEqual([[100, false, 1], [101, true, 0]]);
  });

  it("does not fold processes that ran different commands", () => {
    const [call] = buildCommands([loop(3, (i) => ({ args: ["wc", "-l", `f${String(i)}`] }))], QUIET);
    expect(call.rows.filter((r) => r.node.path === "/usr/bin/wc")).toHaveLength(3);
  });
});

describe("searchCommands", () => {
  // spec:web-ui/ai-agent-session-view-navigation/search-expands-to-what-it-finds
  it("finds matching processes, folded ones included, and counts them per call", () => {
    const calls = buildCommands([...realSession(), loop(4)], QUIET);
    const hits = searchCommands(calls, "  SLEEP ");
    // Each call's own command counts once: (sleep 47 &) and its sleep; nohup sleep 48's command, nohup and sleep; and the sh -c call's
    // command, sh and bash (both running "sleep 1; ..."), and its sleep.
    expect(hits.byGroup).toEqual(new Map([["row:2298325", 2], ["row:2298439", 3], ["row:2298447", 4]]));
    const wc = searchCommands(calls, "wc -l");
    expect(wc.byGroup.get("row:1")).toBe(5);
    expect([...wc.rows].map((r) => r.node.id)).toEqual([100]);
  });

  it("matches regardless of case", () => {
    const shout = proc(5, 5, 5, "/bin/echo", ["echo", "Hello World"], [], { tool_call_group: 5 });
    expect(searchCommands(buildCommands([shout], QUIET), "hello world").byGroup.get("row:5")).toBe(2);
  });

  it("finds nothing for an empty query", () => {
    const hits = searchCommands(buildCommands(realSession(), QUIET), "   ");
    expect(hits.rows.size).toBe(0);
    expect(hits.byGroup.size).toBe(0);
  });

  it("reports a row whose descendant matched, so a capped list keeps it", () => {
    const calls = buildCommands(realSession(), QUIET);
    // Only the sleep matches its path; the bash above it runs "sleep 1; ..." but is not /bin/sleep.
    const hits = searchCommands(calls, "/bin/sleep");
    const bash = calls[4].rows[1];
    expect(hits.rows.has(bash)).toBe(false);
    expect(containsHit(bash, hits)).toBe(true);
    expect(containsHit(bash.children[0], hits)).toBe(true);
    expect(containsHit(calls[0].rows[0], hits)).toBe(false);
  });
});

describe("buildProcessForest", () => {
  // The agent as the session tree read names it (issue #1334): no session marker, and the creator of every command's root.
  const agent = proc(9000, 5000, 0, "/Users/victor/.local/share/claude/versions/2.1.296", ["claude"], [], { agent_session_id: undefined });
  const createdByAgent = (roots: ProcessNode[]) => roots.map((r) => ({ ...r, ppid: 5000, parent_process_id: 9000 }));

  // spec:web-ui/session-processes-view/every-process-is-listed-under-the-agent-that-ran-it
  it("roots every process at the agent, in fork order, with nothing hidden or folded", () => {
    const forest = buildProcessForest(createdByAgent(realSession()), [agent], QUIET);
    expect(forest).toHaveLength(1);
    expect(forest[0].node.id).toBe(9000);
    expect(forest[0].agent).toBe(true);
    expect(forest[0].children.some((r) => r.agent)).toBe(false);
    // Every one of the capture's 16 processes, plus the agent: the wrappers and the subshell's zsh copy are listed, not hidden.
    expect(countRows(forest)).toBe(17);
    expect(forest[0].children.map((r) => r.node.pid)).toEqual([80727, 80730, 80838, 80840, 80843]);
    expect(outline([forest[0].children[1]])).toEqual(["/bin/zsh", "  /bin/zsh", "    /bin/sleep"]);
    const loop = proc(1, 1, 1, "/bin/zsh", ["/bin/zsh", "-c", "eval 'wc -l f; wc -l f'"], [
      proc(2, 2, 2, "/usr/bin/wc", ["wc", "-l", "f"]), proc(3, 3, 3, "/usr/bin/wc", ["wc", "-l", "f"]),
    ]);
    const [loopRoot] = buildProcessForest(createdByAgent([loop]), [agent], QUIET)[0].children;
    expect(loopRoot.children.map((r) => r.folded)).toEqual([undefined, undefined]);
  });

  // The agent's own processes (issue #1361) are the agent node's children in the read: listed under it only when asked for, marked
  // own down their subtree, among the session's roots in fork order, and counted either way.
  // spec:web-ui/agent-own-processes-view/the-agent-s-own-processes-are-counted-and-listed-on-request
  it("lists the agent's own processes under it only when asked, marked as its own, and counts them", () => {
    const snapshot = proc(9101, 5101, 1, "/bin/zsh", ["/bin/zsh", "-c", "-l", "SNAPSHOT_FILE=x"], [proc(9102, 5102, 2, "/usr/bin/env", ["env"])]);
    const scan = proc(9103, 5103, 900_000, "/opt/homebrew/bin/rg", ["rg", "--files"]);
    const withOwn = { ...agent, children: [snapshot, scan] };
    expect(countOwn([withOwn])).toBe(3);
    expect(countOwn([agent])).toBe(0);

    const hidden = buildProcessForest(createdByAgent(realSession()), [withOwn], QUIET);
    expect(countRows(hidden)).toBe(17);
    expect(hidden[0].children.some((r) => r.own)).toBe(false);

    const shown = buildProcessForest(createdByAgent(realSession()), [withOwn], QUIET, true);
    expect(countRows(shown)).toBe(20);
    const children = shown[0].children;
    const forkTimes = children.map((r) => r.node.fork_time_ns);
    expect(forkTimes).toEqual([...forkTimes].sort((a, b) => a - b));
    const snapRow = children.find((r) => r.node.id === 9101);
    expect(snapRow?.own).toBe(true);
    expect(snapRow?.children[0].own).toBe(true);
    expect(children.filter((r) => !r.own).every((r) => r.own === undefined)).toBe(true);
    expect(children.filter((r) => r.own)).toHaveLength(2);
  });

  it("lists a root no listed agent created after the agents, and every root when the agent was not seen", () => {
    const [stray] = realSession();
    const forest = buildProcessForest([...createdByAgent(realSession().slice(1)), stray], [agent], QUIET);
    expect(forest.map((r) => r.node.id)).toEqual([9000, stray.id]);
    expect(buildProcessForest(realSession(), [], QUIET).map((r) => r.node.pid)).toEqual([80727, 80730, 80838, 80840, 80843]);
  });

  it("keeps a process launchd adopted under the process that created it", () => {
    // A double fork: the subshell exits before its child execs sleep, so launchd adopts the sleep.
    const daemon = proc(3, 30, 3, "/bin/sleep", ["sleep", "47"], [], { ppid: 1, reparented: true });
    const call = proc(1, 10, 1, "/bin/zsh", ["/bin/zsh", "-c", "eval '(sleep 47 &)'"], [proc(2, 20, 2, "/bin/zsh", undefined, [daemon])]);
    const [root] = buildProcessForest(createdByAgent([call]), [agent], QUIET)[0].children;
    expect(outline([root])).toEqual(["/bin/zsh", "  /bin/zsh", "    /bin/sleep"]);
  });
});

describe("buildCommands folding", () => {
  // Two identical sleeps under one shell, one launchd adopted: folding them would show one badge for both, or none.
  it.each([
    { order: "adopted first", adopted: [true, false] },
    { order: "adopted second", adopted: [false, true] },
  ])("never folds a process launchd adopted into an identical sibling ($order)", ({ adopted }) => {
    const sleeps = adopted.map((reparented, i) => proc(2 + i, 20 + i, 2 + i, "/bin/sleep", ["sleep", "47"], [], { reparented }));
    const call = proc(1, 10, 1, "/bin/zsh", ["/bin/zsh", "-c", "eval 'sleep 47 & sleep 47 &'"], sleeps, { tool_call_group: 10 });
    const [group] = buildCommands([call], QUIET);
    expect(group.rows.map((r) => [r.node.reparented ?? false, r.folded?.length ?? 0])).toEqual(adopted.map((a) => [a, 0]));
  });
});

describe("services", () => {
  it("marks a service, never folds it, and does not badge its user as a privilege change", () => {
    // TextEdit (uid 501) and two identical WebContent services launchd started for it, running as another user.
    const svc = (id: number) => proc(id, id, 3, "/System/WebKit/com.apple.WebKit.WebContent", ["WebContent"], [], { uid: 260 });
    const app = proc(2, 2, 2, "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit", ["TextEdit"], [svc(3), svc(4)]);
    const call = proc(1, 1, 1, "/bin/zsh", ["/bin/zsh", "-c", "eval 'open -a TextEdit'"], [app], { tool_call_group: 1 });
    const [group] = buildCommands([call], { verbose: true, services: new Set([3, 4]) });
    const listedApp = group.rows[0].children[0];
    expect(listedApp.children.map((r) => [r.service, r.folded?.length ?? 0, r.uidChange])).toEqual([[true, 0, undefined], [true, 0, undefined]]);
  });
});

describe("searchRows", () => {
  it("finds a query anywhere in the forest, and nothing for an empty one", () => {
    const forest = buildProcessForest(realSession(), [], QUIET);
    const hits = searchRows(forest, " SLEEP 47 ");
    expect([...hits.rows].map((r) => r.node.id)).toEqual([2298325, 2298327]);
    expect(searchRows(forest, "  ").rows.size).toBe(0);
  });
});
