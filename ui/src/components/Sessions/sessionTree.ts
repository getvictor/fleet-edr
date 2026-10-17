// Shaping an AI agent session's process forest into what the session view shows (issue #1284): one group per command the agent ran,
// labelled with that command, with the shell plumbing that ran it hidden unless the operator asks for it. A group is what the sensor
// observed; the tool call the agent reported for it, read from its transcript, is paired with it separately (toolCallJoin.ts, #1333).
//
// The server reads the session as a forest built by creator. The agent process itself carries no session marker, so each command's
// shell is a root, and everything that command started (a pipeline's commands, a daemon it double-forked or nohup'ed) hangs under it.

import type { ProcessNode } from "../../types";
import { commandLine, isShellPath, toolCommand } from "./toolCommand";

// SessionRow is one process the view lists, with the rows under it.
export interface SessionRow {
  node: ProcessNode;
  children: SessionRow[];
  // uidChange is set when the process runs as a different user from the process that created it: a privilege change, such as sudo
  // to root, the view badges.
  uidChange?: { from: number; to: number };
  // inferred is set when the row was launched by launchd for the process it is listed under (issue #1286): linked by timing and
  // target, not lineage.
  inferred?: boolean;
  // service is set when launchd started the row for the app it is listed under, which the row names as responsible (issue #1340).
  service?: boolean;
  // folded holds the identical siblings folded into this row, in fork order: processes that ran the same command under the same
  // creator, ran nothing of their own and were not flagged. The row stands for all of them.
  folded?: ProcessNode[];
  // agent is set on the agent process's own row in the Processes view (issue #1335), so the row says what it is.
  agent?: boolean;
  // own is set on a process the agent ran for itself, with no session marker (issue #1361): a plugin scan, a shell snapshot, its
  // fork daemon. Listed under the agent, apart from the commands the session ran.
  own?: boolean;
}

// Command is one group: the processes a single command the agent ran started.
export interface Command {
  // key identifies the group by the row of the root that started it.
  key: string;
  // command is what the agent ran: the wrapper's eval argument, or the root's own command line when it is not such a wrapper.
  command: string;
  // fromAgent is set when the group's root is the agent's wrapper shell, so its command is one the agent ran as a Bash call.
  fromAgent: boolean;
  // uid is the user the group's root ran as.
  uid?: number;
  startNs: number;
  // lastNs is the group's last observed activity: its latest exit, exec or fork.
  lastNs: number;
  // processCount counts every process in the group, including the plumbing the view hides.
  processCount: number;
  // processIds are the rows of every process in the group, hidden plumbing included, so the view can count the group's alerts.
  processIds: number[];
  rows: SessionRow[];
}

// RowShape is how rows are listed: verbose lists the shell plumbing too, and keep names processes never hidden as plumbing, so a
// process an alert was raised on is always listed.
export interface RowShape {
  verbose: boolean;
  keep?: ReadonlySet<number>;
  // incomplete is set when the read left out processes or alerts (a truncated tree, a failed or capped alert read). Folding is then
  // off: a row that looks identical to its siblings may have started a process or carried an alert the view never saw.
  incomplete?: boolean;
  // inferred names the rows an inferred launch placed under their launcher, so each is marked as inferred rather than lineage.
  inferred?: ReadonlySet<number>;
  // services names the rows placed under the app responsible for them (issue #1340).
  services?: ReadonlySet<number>;
  // unfolded lists every process on its own row, for the Processes view (issue #1335): nothing is folded into an identical sibling.
  unfolded?: boolean;
}

// SessionSummary is what the view's header says about the whole session, read from its processes.
export interface SessionSummary {
  agentName?: string;
  agentVersion?: string;
  // project is the working directory of the session's first command.
  project?: string;
  firstNs?: number;
  lastNs?: number;
  processCount: number;
}

function byForkTime(a: ProcessNode, b: ProcessNode): number {
  return a.fork_time_ns - b.fork_time_ns || a.id - b.id;
}

// lastActivityNs is when a process was last seen doing something. Only an observed exit counts: the server synthesizes the others
// (a stale process closed by its sweep hours later, a pid reused), and their time says when the server noticed, not when the process
// ran. A re-exec's exit is the moment the next image started.
export function lastActivityNs(node: ProcessNode): number {
  const observedExit = node.exit_reason === "event" || node.exit_reason === "reexec" ? node.exit_time_ns : undefined;
  return observedExit ?? node.exec_time_ns ?? node.fork_time_ns;
}

// walk visits a node and everything under it.
function walk(node: ProcessNode, visit: (n: ProcessNode) => void): void {
  visit(node);
  for (const child of node.children ?? []) walk(child, visit);
}

// isShellCopy reports a fork of a shell that never exec'd: the copy a shell makes to run a subshell or a background job. It carries
// its creator's image and no command of its own. A fork carries no user of its own either, so it runs as its creator did; one that
// reports another user changed privilege, which is not plumbing.
function isShellCopy(node: ProcessNode, creator: ProcessNode, creatorUid: number | undefined): boolean {
  const sameUser = node.uid === undefined || node.uid === creatorUid;
  return node.exec_time_ns === undefined && node.path === creator.path && sameUser && isShellPath(node.path);
}

function hidden(node: ProcessNode, isPlumbing: boolean, shape: RowShape): boolean {
  return isPlumbing && !shape.verbose && !(shape.keep?.has(node.id) ?? false);
}

// row lists a process. creatorUid is the user its creator ran as, when known, for the privilege comparison.
function row(node: ProcessNode, creatorUid: number | undefined, shape: RowShape): SessionRow {
  const listed: SessionRow = { node, children: visibleRows(node, node.uid ?? creatorUid, shape) };
  if (shape.inferred?.has(node.id)) listed.inferred = true;
  if (shape.services?.has(node.id)) listed.service = true;
  // An inferred launch's launcher, or a service's app, is not its creator (launchd is), so a different user across that edge is no
  // privilege change.
  if (!listed.inferred && !listed.service && creatorUid !== undefined && node.uid !== undefined && node.uid !== creatorUid) {
    listed.uidChange = { from: creatorUid, to: node.uid };
  }
  return listed;
}

// foldKey identifies a row that can be folded with its identical siblings: a process that started nothing, changed no privilege, was
// not adopted by launchd and carries no alert. Null for any other row: a folded process shows no badge of its own.
function foldKey(listed: SessionRow, shape: RowShape): string | null {
  if (shape.incomplete || shape.unfolded || listed.inferred || listed.service || listed.node.reparented || listed.children.length > 0 || listed.uidChange || (shape.keep?.has(listed.node.id) ?? false)) {
    return null;
  }
  // How each ended is part of the key: a failed run must not hide behind a successful one.
  const outcome = `${listed.node.exit_reason ?? ""}:${String(listed.node.exit_code ?? "")}`;
  return `${listed.node.path}\u0000${commandLine(listed.node.path, listed.node.args)}\u0000${outcome}`;
}

// foldRows folds identical sibling rows into the first of them, keeping the list's order. A loop that runs the same command a
// thousand times lists one row that says so, rather than a thousand.
function foldRows(rows: SessionRow[], shape: RowShape): SessionRow[] {
  const firstByKey = new Map<string, SessionRow>();
  const out: SessionRow[] = [];
  for (const listed of rows) {
    const key = foldKey(listed, shape);
    const first = key === null ? undefined : firstByKey.get(key);
    if (first === undefined) {
      if (key !== null) firstByKey.set(key, listed);
      out.push(listed);
    } else {
      // Appended in place, so folding a long loop stays linear.
      first.folded ??= [];
      first.folded.push(listed.node, ...(listed.folded ?? []));
    }
  }
  return out;
}

// visibleRows lists a node's children as the view shows them. A hidden shell copy is replaced by its own children. uid is the user
// the node runs as: its own when it reports one, else the one it inherited, since a fork that never exec'd reports none.
function visibleRows(creator: ProcessNode, uid: number | undefined, shape: RowShape): SessionRow[] {
  const rows: SessionRow[] = [];
  for (const child of [...(creator.children ?? [])].sort(byForkTime)) {
    if (hidden(child, isShellCopy(child, creator, uid), shape)) {
      rows.push(...visibleRows(child, child.uid ?? uid, shape));
    } else {
      rows.push(row(child, uid, shape));
    }
  }
  return foldRows(rows, shape);
}

// rootRows is what a command's root contributes: a hidden wrapper shell is the group's header rather than a row, so its children
// stand in its place. The root's creator is the agent, which the session does not hold.
function rootRows(root: ProcessNode, shape: RowShape): SessionRow[] {
  if (hidden(root, toolCommand(root.args) !== null, shape)) return visibleRows(root, root.uid, shape);
  return [row(root, undefined, shape)];
}

// buildCommands groups the session's forest by command, in the order the commands started. Each command's leader (the shell that
// leads the process group keying it) starts a group. A root whose creator was not read joins the latest group its key names that
// started before it, so a command stays one group even when part of its tree arrived without its parent. The key is a process-group id,
// which a long session can reuse, so a later leader with the same key starts a group of its own rather than joining the earlier one.
export function buildCommands(roots: readonly ProcessNode[], shape: RowShape): Command[] {
  const groups: Command[] = [];
  const latestByKey = new Map<number, Command>();
  for (const root of [...roots].sort(byForkTime)) {
    const key = root.tool_call_group;
    let group = key === undefined || root.pid === key ? undefined : latestByKey.get(key);
    if (group === undefined) {
      const agentCommand = toolCommand(root.args);
      group = {
        key: `row:${String(root.id)}`,
        command: agentCommand ?? commandLine(root.path, root.args),
        fromAgent: agentCommand !== null,
        uid: root.uid,
        startNs: root.fork_time_ns,
        lastNs: root.fork_time_ns,
        processCount: 0,
        processIds: [],
        rows: [],
      };
      groups.push(group);
      if (key !== undefined) latestByKey.set(key, group);
    }
    const into = group;
    walk(root, (n) => {
      into.processCount += 1;
      into.processIds.push(n.id);
      into.lastNs = Math.max(into.lastNs, lastActivityNs(n));
    });
    into.rows.push(...rootRows(root, shape));
  }
  return groups;
}

// buildProcessForest lists every process a session ran as one tree for the Processes view (issue #1335): each agent process, with the
// roots it created beneath it in fork order, then any root no listed agent created (a launch whose launcher was not read, a command
// whose agent was not seen). Nothing is hidden or folded: the shape is verbose and unfolded, whatever the caller passes. With
// showOwn, each agent also lists the processes it ran for itself (issue #1361), marked own, among the session's in fork order.
export function buildProcessForest(
  roots: readonly ProcessNode[], agents: readonly ProcessNode[], shape: RowShape, showOwn = false,
): SessionRow[] {
  const full: RowShape = { ...shape, verbose: true, unfolded: true };
  const sorted = [...roots].sort(byForkTime);
  const claimed = new Set<number>();
  const forest: SessionRow[] = [...agents].sort(byForkTime).map((agent) => {
    const created = sorted.filter((root) => root.parent_process_id === agent.id);
    for (const root of created) claimed.add(root.id);
    const own = showOwn ? (agent.children ?? []).map((n) => markOwn(row(n, agent.uid, full))) : [];
    const children = [...created.map((root) => row(root, agent.uid, full)), ...own]
      .sort((a, b) => byForkTime(a.node, b.node));
    return { node: agent, agent: true, children };
  });
  for (const root of sorted) {
    if (!claimed.has(root.id)) forest.push(row(root, undefined, full));
  }
  return forest;
}

// markOwn marks a row of the agent's own processes, and everything under it, as the agent's own.
function markOwn(listed: SessionRow): SessionRow {
  listed.own = true;
  listed.children.forEach(markOwn);
  return listed;
}

// countOwn counts the processes the session's agents ran for themselves (issue #1361): the processes under each agent node.
export function countOwn(agents: readonly ProcessNode[]): number {
  const count = (nodes: readonly ProcessNode[]): number => nodes.reduce((sum, n) => sum + 1 + count(n.children ?? []), 0);
  return agents.reduce((sum, agent) => sum + count(agent.children ?? []), 0);
}

// countRows counts the processes a forest lists, folded ones included.
export function countRows(rows: readonly SessionRow[]): number {
  return rows.reduce((sum, listed) => sum + 1 + (listed.folded?.length ?? 0) + countRows(listed.children), 0);
}

// matches reports whether a process's command line or path contains the query, ignoring case. query is already lower case.
function matches(node: ProcessNode, query: string): boolean {
  return commandLine(node.path, node.args).toLowerCase().includes(query) || node.path.toLowerCase().includes(query);
}

// SearchHits is what a search found in the session: the rows that match, and per command how many of its processes match.
export interface SearchHits {
  // rows are the listed rows whose process, or a process folded into them, matches.
  rows: ReadonlySet<SessionRow>;
  // byGroup counts the matching processes in each group, by its key; a group whose command matches counts as one more.
  byGroup: ReadonlyMap<string, number>;
}

// rowMatcher counts the processes a row and everything under it hold that match query, adding each matching row to rows.
function rowMatcher(query: string, rows: Set<SessionRow>): (listed: SessionRow) => number {
  const visit = (listed: SessionRow): number => {
    const own = [listed.node, ...(listed.folded ?? [])].filter((n) => matches(n, query)).length;
    if (own > 0) rows.add(listed);
    return listed.children.reduce((sum, child) => sum + visit(child), own);
  };
  return visit;
}

// searchRows finds a query in a forest of rows, for the Processes view, which has no groups. An empty query finds nothing.
export function searchRows(forest: readonly SessionRow[], rawQuery: string): SearchHits {
  const query = rawQuery.trim().toLowerCase();
  const rows = new Set<SessionRow>();
  if (query !== "") forest.forEach(rowMatcher(query, rows));
  return { rows, byGroup: new Map() };
}

// searchCommands finds a query in the groups as listed. An empty query finds nothing.
export function searchCommands(groups: readonly Command[], rawQuery: string): SearchHits {
  const query = rawQuery.trim().toLowerCase();
  const rows = new Set<SessionRow>();
  const byGroup = new Map<string, number>();
  if (query === "") return { rows, byGroup };
  const visit = rowMatcher(query, rows);
  for (const group of groups) {
    const count = group.rows.reduce((sum, listed) => sum + visit(listed), group.command.toLowerCase().includes(query) ? 1 : 0);
    if (count > 0) byGroup.set(group.key, count);
  }
  return { rows, byGroup };
}

// containsHit reports whether a row or anything under it matched, so a capped list still shows it.
export function containsHit(listed: SessionRow, hits: SearchHits): boolean {
  return hits.rows.has(listed) || listed.children.some((child) => containsHit(child, hits));
}

// containsProcess reports whether a row or anything under it is one of ids, so a capped list still shows a flagged process.
export function containsProcess(listed: SessionRow, ids: ReadonlyMap<number, unknown>): boolean {
  return ids.has(listed.node.id) || listed.children.some((child) => containsProcess(child, ids));
}

// forkSpan is the first and last fork time of a row and every process folded into it. Folded members are not in fork order: a run
// hoisted out of a hidden shell copy joins the run before it.
export function forkSpan(listed: SessionRow): { firstNs: number; lastNs: number } {
  const forks = [listed.node, ...(listed.folded ?? [])].map((n) => n.fork_time_ns);
  return { firstNs: Math.min(...forks), lastNs: Math.max(...forks) };
}

// summarizeSession reads the header's facts from the session's processes. The agent is named on every stamped process; the project
// is where the first command ran.
export function summarizeSession(roots: readonly ProcessNode[]): SessionSummary {
  const summary: SessionSummary = { processCount: 0 };
  const first = [...roots].sort(byForkTime)[0] as ProcessNode | undefined;
  summary.project = first?.cwd;
  for (const root of roots) {
    walk(root, (n) => {
      summary.processCount += 1;
      summary.agentName ??= n.agent_name;
      summary.agentVersion ??= n.agent_version;
      summary.firstNs = Math.min(summary.firstNs ?? n.fork_time_ns, n.fork_time_ns);
      summary.lastNs = Math.max(summary.lastNs ?? 0, lastActivityNs(n));
    });
  }
  return summary;
}
