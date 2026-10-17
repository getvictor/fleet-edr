import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import "./SessionView.scss";
import { getAgentSessionLineage, getAgentToolCalls, getSessionTree, listAgentSessions, listAlerts } from "../../api";
import type { AgentSessionLineage, AgentSessionSummary, AgentToolCall, Alert, ProcessNode, TreeResponse } from "../../types";
import { PageHeader } from "../ui/PageHeader";
import { Toggle } from "../ui/Toggle";
import { Input } from "../ui/Input";
import { Button } from "../ui/Button";
import { ProcessDetail } from "../ProcessDetail";
import { ActivityTabs } from "../Activity/ActivityTabs";
import { Badge } from "../ui/Badge";
import { EmptyState } from "../ui/Table";
import { severityBadgeVariant, severityRank } from "../ui/severity";
import { formatNs, executableName, plural } from "../Search/format";
import { findNodeByDbId } from "../ProcessTree.helpers";
import { applyLaunchLinks } from "../launchLinks";
import { useHostNames } from "../useHostNames";
import { NANOSECONDS_PER_MILLISECOND } from "../../constants";
import {
  buildCommands,
  containsHit,
  containsProcess,
  forkSpan,
  lastActivityNs,
  searchCommands,
  searchRows,
  buildProcessForest,
  countOwn,
  countRows,
  summarizeSession,
  type SearchHits,
  type SessionRow,
  type Command,
} from "./sessionTree";
import { commandLine } from "./toolCommand";
import { joinToolCalls, type ToolCallMatch } from "./toolCallJoin";
import { sessionPath } from "./sessionPath";

// AUTO_EXPAND_GROUPS is the most commands a session can have and still open with every one expanded. A longer session opens with
// only the commands an alert was raised in expanded, so the operator starts from what was flagged.
const AUTO_EXPAND_GROUPS = 10;
// ROW_CAP is how many processes a list shows before "Show more": a command that ran a long loop opens on its first rows rather than on
// all of them. A row that holds a search hit is shown regardless.
const ROW_CAP = 20;

// SESSION_LENSES are the session's three views, in order: what it ran as commands, every process as one tree, and what it touched.
type SessionLens = "commands" | "processes" | "activity";
const SESSION_LENSES: readonly { lens: SessionLens; label: string }[] = [
  { lens: "commands", label: "Commands" },
  { lens: "processes", label: "Processes" },
  { lens: "activity", label: "Activity" },
];

// REPORTED_LABEL marks what the agent reported about a command, as distinct from what the sensor observed (issue #1333).
const REPORTED_LABEL = "Reported by agent";
const REPORTED_TITLE = "From the agent's session transcript, which the agent and its user can write; not observed by the sensor";

// OWN_SUMMARY and OWN_TITLE say what the agent's own processes are (issue #1361): what the agent ran for itself, not commands the
// session ran.
const OWN_SUMMARY = "Plugin scans, shell snapshots and other work the agent ran for itself, not commands the session ran.";
const OWN_TITLE = "The agent ran this for itself. It carries no session marker and is not a command the session ran.";

// REPARENTED_TITLE explains a reparented badge: the server marks a process launchd adopted (issue #1280), and the views list it
// under the process that created it, not under launchd.
const REPARENTED_TITLE = "launchd (pid 1) adopted it after the process that created it exited, so its parent is now pid 1; it is " +
  "listed under the process that created it";

// SERVICE_TITLE explains a service badge: launchd started the row for the app it is listed under, which the row names as responsible
// (issue #1340), so the link is the OS's own record, not an inference.
const SERVICE_TITLE = "launchd started it for the app it is listed under, which macOS records as responsible for it";

// INFERRED_LAUNCH_TITLE explains an inferred launch's badge: the row is listed under its launcher, which is not its creator.
const INFERRED_LAUNCH_TITLE =
  "Started by launchd moments after the process it is listed under asked for it: linked by timing and target, not lineage";
// MAX_SESSION_ALERTS bounds the session's alert read. One more is asked for, so a session with more is reported rather than shown as
// if its first page were all of them.
const MAX_SESSION_ALERTS = 1000;

// SessionRead is everything the view reads for one session, kept with the session it was for so another session's results are never
// shown. The tree is required; the record and the alerts decorate it, and their failures are reported without hiding the tree.
interface SessionRead {
  key: string;
  tree?: TreeResponse;
  error?: string;
  record?: AgentSessionSummary;
  alerts?: Alert[];
  alertsFailed?: boolean;
  // alertsTruncated is set when the session has more alerts than were read, so some are not badged.
  alertsTruncated?: boolean;
  // toolCalls are the tool calls the agent reported in its transcript (issue #1288). Unread, the groups simply carry no call.
  toolCalls?: AgentToolCall[];
  // toolCallsTruncated is set when the session recorded more calls than were read, so some groups may show none.
  toolCallsTruncated?: boolean;
  // lineage is the session this one was forked from and the sessions forked from it (issue #1347). Unread, none are linked.
  lineage?: AgentSessionLineage;
}

// SessionRowsContext carries what every row of the view needs: the session's alerts by process, the current search's hits, and the
// selected process, so the nested lists do not thread them through every level.
interface SessionRows {
  hostId: string;
  alertsByProcess: ReadonlyMap<number, Alert[]>;
  hits: SearchHits;
  selectedId: number | null;
  onSelect: (node: ProcessNode) => void;
}

const SessionRowsContext = createContext<SessionRows | null>(null);

function useSessionRows(): SessionRows {
  const rows = useContext(SessionRowsContext);
  if (rows === null) throw new Error("useSessionRows outside SessionView");
  return rows;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : "Unknown error";
}

async function readSession(key: string, hostId: string, sessionId: string): Promise<SessionRead> {
  const [tree, record, alerts, toolCalls, lineage] = await Promise.all([
    getSessionTree(hostId, sessionId).catch((err: unknown) => message(err)),
    listAgentSessions({ host_id: hostId, session: sessionId })
      .then((res) => res.rows[0] as AgentSessionSummary | undefined)
      .catch(() => undefined),
    listAlerts({ host_id: hostId, agent_session: sessionId, limit: MAX_SESSION_ALERTS + 1 }).catch(() => null),
    getAgentToolCalls(hostId, sessionId).catch(() => undefined),
    getAgentSessionLineage(hostId, sessionId).catch(() => undefined),
  ]);
  if (typeof tree === "string") return { key, error: tree };
  // The session's alerts are those on its stamped processes; the agent's own processes (issue #1361) carry no session marker, so their
  // alerts are read by the agent that ran them, to badge them in the Processes view.
  const ownAlerts = await Promise.all((tree.agents ?? []).filter((agent) => (agent.children ?? []).length > 0).map((agent) =>
    listAlerts({ host_id: hostId, agent_process: agent.id, served_session: sessionId, limit: MAX_SESSION_ALERTS + 1 }).catch(() => null)));
  const lists = [alerts, ...ownAlerts];
  return {
    key,
    tree,
    record,
    alerts: lists.flatMap((list) => (list ?? []).slice(0, MAX_SESSION_ALERTS)),
    alertsFailed: lists.includes(null),
    alertsTruncated: lists.some((list) => (list?.length ?? 0) > MAX_SESSION_ALERTS),
    toolCalls: toolCalls?.tool_calls,
    toolCallsTruncated: toolCalls?.truncated,
    lineage,
  };
}

// SessionView answers "what did this agent session do" (issue #1284): the session's processes in the order its commands ran, one
// group per command the agent ran, and under it everything that command started, daemons included. The shell plumbing that runs a
// command is hidden unless the operator turns on verbose. Alerts and privilege changes are badged where they happened, and a command
// an alert was raised in opens expanded. A group is what the sensor observed; the tool call the agent reported for it is labelled as
// reported (issue #1333).
export function SessionView() {
  const { hostId = "", sessionId = "" } = useParams();
  const hostNames = useHostNames();
  const [verbose, setVerbose] = useState(false);
  // showOwn lists the processes the agent ran for itself in the Processes view (issue #1361); off by default, so the session's own
  // work reads first, and their count says how many are one click away.
  const [showOwn, setShowOwn] = useState(false);
  const [query, setQuery] = useState("");
  // view picks what the session's main column shows: its commands, every process it ran as one tree (issue #1335), or the totals of
  // what it touched (issue #1285).
  const [view, setView] = useState<SessionLens>("commands");
  const [selected, setSelected] = useState<{ key: string; node: ProcessNode } | null>(null);
  const readKey = `${hostId}/${sessionId}`;
  const [read, setRead] = useState<SessionRead | null>(null);
  const current = read?.key === readKey ? read : null;
  const tree = current?.tree ?? null;

  useEffect(() => {
    let cancelled = false;
    void readSession(readKey, hostId, sessionId).then((res) => { if (!cancelled) setRead(res); });
    return () => { cancelled = true; };
  }, [hostId, sessionId, readKey]);

  const alertsByProcess = useMemo(() => {
    const byProcess = new Map<number, Alert[]>();
    for (const alert of current?.alerts ?? []) byProcess.set(alert.process_id, [...(byProcess.get(alert.process_id) ?? []), alert]);
    return byProcess;
  }, [current?.alerts]);
  // What launchd started for a command's open or launchctl is listed under it, marked inferred (issue #1286).
  const logical = useMemo(() => (tree ? applyLaunchLinks(tree.roots, tree.links) : null), [tree]);
  const groups = useMemo(
    () => {
      if (!tree || !logical) return [];
      const incomplete = tree.truncated || current === null || current.alertsFailed === true || current.alertsTruncated === true
        || beganBeforeRetention(current);
      return buildCommands(logical.roots, {
        verbose, keep: new Set(alertsByProcess.keys()), incomplete, inferred: logical.inferred, services: logical.services,
      });
    },
    [tree, logical, verbose, alertsByProcess, current],
  );
  const forest = useMemo(
    () => (tree && logical
      ? buildProcessForest(logical.roots, tree.agents ?? [], { verbose: true, inferred: logical.inferred, services: logical.services },
        showOwn)
      : []),
    [tree, logical, showOwn],
  );
  const summary = useMemo(() => summarizeSession(tree?.roots ?? []), [tree]);
  const hits = useMemo(
    () => (view === "processes" ? searchRows(forest, query) : searchCommands(groups, query)),
    [view, forest, groups, query],
  );
  // A selection belongs to the session it was made in.
  const selectedNode = selected?.key === readKey && tree !== null ? selected.node : null;
  const rowsContext = useMemo<SessionRows>(
    () => ({
      hostId,
      alertsByProcess,
      hits,
      selectedId: selectedNode?.id ?? null,
      onSelect: (node: ProcessNode) => { setSelected({ key: readKey, node }); },
    }),
    [hostId, alertsByProcess, hits, selectedNode, readKey],
  );

  const record = current?.record;
  const agentName = record?.agent_name ?? summary.agentName;
  const agentVersion = record?.agent_version ?? summary.agentVersion;
  const title = agentName ? `${agentName}${agentVersion ? ` ${agentVersion}` : ""}` : "Agent session";
  const firstNs = record?.first_seen_ns ?? summary.firstNs;
  const lastNs = Math.max(record?.last_seen_ns ?? 0, summary.lastNs ?? 0) || undefined;
  const project = record?.cwd ?? summary.project;
  const subtitle = (
    <span className="session-view__facts">
      {project && <span className="session-view__mono">{project}</span>}
      <span>{hostNames.get(hostId) ?? hostId}</span>
      {firstNs !== undefined && lastNs !== undefined && <span>{`${formatNs(firstNs)} to ${formatNs(lastNs)}`}</span>}
      {tree && <span>{plural(summary.processCount, "process", "processes")}</span>}
      {record?.agent_pid !== undefined && <span>agent pid {record.agent_pid}</span>}
      <span className="session-view__mono" title={sessionId}>Session {sessionId}</span>
    </span>
  );

  return (
    <div className="session-view">
      <Link to="/agent-sessions" className="session-view__back">All agent sessions</Link>
      <PageHeader
        title={title}
        subtitle={subtitle}
        actions={(
          <div className="session-view__actions">
            <Input
              type="search"
              aria-label="Search this session"
              placeholder={view === "processes" ? "Search processes" : "Search commands"}
              value={query}
              onChange={(e) => { setQuery(e.target.value); }}
            />
            {/* The plumbing toggle belongs to Commands alone: Processes lists every process already. It keeps its space in every view,
                hidden rather than removed, so the header wraps alike in all three and the view switcher below never moves. */}
            <span style={view === "commands" ? undefined : { visibility: "hidden" }}>
              <Toggle
                id="session-verbose"
                label="Show shell plumbing"
                checked={verbose}
                onChange={(e) => { setVerbose(e.target.checked); }}
              />
            </span>
          </div>
        )}
      />
      <SessionLineageLine hostId={hostId} lineage={current?.lineage} />
      <SessionNotices read={current} />
      <SessionRowsContext.Provider value={rowsContext}>
        <div className="session-view__layout">
          <div className="session-view__main">
            <div role="group" aria-label="Session view" className="session-view__views">
              {SESSION_LENSES.map(({ lens: v, label }) => (
                <button
                  key={v}
                  type="button"
                  aria-pressed={view === v}
                  className="session-view__view"
                  onClick={() => { setView(v); }}
                >
                  {label}
                </button>
              ))}
            </div>
            {view === "commands" && <SessionBody read={current} groups={groups} />}
            {view === "processes" && <ProcessesBody read={current} forest={forest} showOwn={showOwn} onShowOwn={setShowOwn} />}
            {view === "activity" && (
              <ActivityTabs
                label="Session activity"
                hostId={hostId}
                scope={{ kind: "session", session: sessionId }}
                onProcess={(id) => {
                  // The agent is not among the roots, and its own edits are what the Files tab lists most (issue #1287).
                  const node = tree ? findNodeByDbId([...(tree.agents ?? []), ...tree.roots], id) : null;
                  if (node) rowsContext.onSelect(node);
                }}
              />
            )}
          </div>
          {selectedNode && (
            <aside className="session-view__detail">
              <Link className="session-view__graph-link" to={hostHref(hostId, selectedNode.id, selectedNode.fork_time_ns)}>
                Open in host graph
              </Link>
              <ProcessDetail
                key={selectedNode.id}
                hostId={hostId}
                node={selectedNode}
                onClose={() => { setSelected(null); }}
                timelineHref={timelineHref(hostId, selectedNode)}
              />
            </aside>
          )}
        </div>
      </SessionRowsContext.Provider>
    </div>
  );
}

// SessionLineageLine links a forked session to the session it was forked from, and a session to those forked from it (issue #1347).
// A fork is a session of its own: its commands are its own, and the history it copied from its parent is listed under the parent.
function SessionLineageLine({ hostId, lineage }: { readonly hostId: string; readonly lineage: AgentSessionLineage | undefined }) {
  const parent = lineage?.forked_from_session_id;
  const forks = lineage?.forked_session_ids ?? [];
  if (!parent && forks.length === 0) return null;
  const link = (session: string) => (
    <Link key={session} className="session-view__mono" to={sessionPath(hostId, session)} title={session}>
      {`Session ${session}`}
    </Link>
  );
  return (
    <p className="session-view__lineage">
      {parent && <span>Forked from {link(parent)}</span>}
      {forks.length > 0 && (
        <span>
          {"Forked into "}
          {forks.map((session, i) => <span key={session}>{i > 0 && ", "}{link(session)}</span>)}
        </span>
      )}
    </p>
  );
}

// SessionNotices says what the view is not showing: processes past the read's limit, processes retention removed, and alerts that
// could not be read.
// beganBeforeRetention reports a session first seen before the retention cutoff, so processes it ran that finished before then are
// gone from the read.
function beganBeforeRetention(read: SessionRead): boolean {
  const retainedFrom = read.tree?.retained_from_ns;
  return retainedFrom !== undefined && read.record !== undefined && read.record.first_seen_ns < retainedFrom;
}

function SessionNotices({ read }: { readonly read: SessionRead | null }) {
  const tree = read?.tree;
  if (!tree) return null;
  const retainedFrom = tree.retained_from_ns;
  return (
    <>
      {tree.truncated && (
        <p className="session-view__notice" role="status">
          Showing the first {tree.returned.toLocaleString()} of {tree.total_matched_capped ? "more than " : ""}
          {tree.total_matched.toLocaleString()} processes in this session.
        </p>
      )}
      {retainedFrom !== undefined && beganBeforeRetention(read) && (
        <p className="session-view__notice" role="status">
          This session began before {formatNs(retainedFrom)}, and processes that finished before then have been removed by retention.
        </p>
      )}
      {read.alertsFailed && (
        <p className="session-view__notice" role="status">This session&apos;s alerts could not be loaded, so none are shown.</p>
      )}
      {read.toolCallsTruncated && (
        <p className="session-view__notice" role="status">
          The agent reported more tool calls than are read, so some commands may show without the tool call the agent reported for
          them.
        </p>
      )}
      {read.alertsTruncated && (
        <p className="session-view__notice" role="status">
          This session has more than {MAX_SESSION_ALERTS.toLocaleString()} alerts; only the {MAX_SESSION_ALERTS.toLocaleString()} most
          recent are badged.
        </p>
      )}
    </>
  );
}

function SessionBody({ read, groups }: { readonly read: SessionRead | null; readonly groups: Command[] }) {
  const { alertsByProcess } = useSessionRows();
  if (read?.error) return <EmptyState>Error: {read.error}</EmptyState>;
  if (!read?.tree) return <EmptyState>Loading...</EmptyState>;
  if (groups.length === 0) return <EmptyState>No processes are recorded for this session.</EmptyState>;
  const expandAll = groups.length <= AUTO_EXPAND_GROUPS;
  const matches = joinToolCalls(groups, read.toolCalls ?? []);
  return (
    <ol className="session-view__calls">
      {groups.map((group) => {
        const alerts = group.processIds.flatMap((id) => alertsByProcess.get(id) ?? []);
        return (
          <CommandGroup
            key={group.key}
            group={group}
            match={matches.get(group.key)}
            alerts={alerts}
            defaultOpen={expandAll || alerts.length > 0}
          />
        );
      })}
    </ol>
  );
}

// ProcessesBody lists every process the session ran as one tree rooted at the agent (issue #1335), with nothing hidden or folded: the
// forensic counterpart to the commands, which group and trim the same processes for reading.
function ProcessesBody({ read, forest, showOwn, onShowOwn }: {
  readonly read: SessionRead | null;
  readonly forest: SessionRow[];
  readonly showOwn: boolean;
  readonly onShowOwn: (show: boolean) => void;
}) {
  if (read?.error) return <EmptyState>Error: {read.error}</EmptyState>;
  if (!read?.tree) return <EmptyState>Loading...</EmptyState>;
  if (forest.length === 0) return <EmptyState>No processes are recorded for this session.</EmptyState>;
  const own = countOwn(read.tree.agents ?? []);
  return (
    <div className="session-view__processes">
      <p className="session-view__processes-summary">{processesSummary(forest)}</p>
      {own > 0 && (
        <div className="session-view__own">
          <Toggle
            id="session-own"
            label={`Show the agent's own processes (${own.toLocaleString()}${read.tree.agent_own_truncated ? "+" : ""})`}
            checked={showOwn}
            onChange={(e) => { onShowOwn(e.target.checked); }}
          />
          <span className="session-view__meta">{OWN_SUMMARY}</span>
        </div>
      )}
      <ProcessRows rows={forest} />
    </div>
  );
}

// processesSummary counts what the Processes view lists and says where it hangs: under the agent, beside it when a root's creator was
// not read, or as roots when the agent was not seen.
function processesSummary(forest: readonly SessionRow[]): string {
  const count = plural(countRows(forest), "process", "processes");
  const beside = forest.filter((r) => !r.agent).length;
  if (beside === forest.length) return `${count}. The agent process was not seen, so its commands are listed as roots`;
  if (beside === 0) return `${count}, under the agent that ran them`;
  return `${count}. ${plural(beside, "root sits", "roots sit")} beside the agent: the process that created ${beside === 1 ? "it" : "them"} ` +
    "was not read";
}

// highestSeverity is the most severe of the alerts' severities, for the group's badge.
function highestSeverity(alerts: readonly Alert[]): string {
  return alerts.reduce((top, a) => (severityRank(a.severity) < severityRank(top) ? a.severity : top), "");
}

// CommandGroup is one command. A search that finds something in it opens it, whatever the operator last chose.
function CommandGroup({ group, match, alerts, defaultOpen }: {
  readonly group: Command;
  readonly match: ToolCallMatch | undefined;
  readonly alerts: readonly Alert[];
  readonly defaultOpen: boolean;
}) {
  const { hits } = useSessionRows();
  const [open, setOpen] = useState(defaultOpen);
  const found = hits.byGroup.get(group.key) ?? 0;
  const expanded = open || found > 0;
  return (
    <li className="session-view__call">
      <button
        type="button"
        className="session-view__call-header"
        aria-expanded={expanded}
        onClick={() => { setOpen(!expanded); }}
      >
        <code className="session-view__command">{group.command}</code>
        <span className="session-view__meta">
          {formatNs(group.startNs)} · {plural(group.processCount, "process", "processes")}
        </span>
        {alerts.length > 0 && (
          <Badge variant={severityBadgeVariant(highestSeverity(alerts))}>{plural(alerts.length, "alert", "alerts")}</Badge>
        )}
        {found > 0 && <span className="session-view__found">{plural(found, "match", "matches")}</span>}
        {match && <AgentCall match={match} />}
      </button>
      {expanded && group.rows.length > 0 && <ProcessRows rows={group.rows} />}
    </li>
  );
}

// AgentCall names the tool call the agent reported for a group (issue #1288): the description the agent gave it and its tool_use_id,
// or, for identical calls of one turn that cannot be told apart, the calls it is one of. It is labelled as reported (issue #1333):
// it comes from the agent's transcript, a file the agent and its user can write, not from the sensor.
function AgentCall({ match }: { readonly match: ToolCallMatch }) {
  if (match.kind === "ambiguous") {
    const ids = match.candidates.map((c) => c.tool_use_id);
    return (
      <span className="session-view__agent-call" title={`One of: ${ids.join(", ")}`}>
        <span className="session-view__reported" title={REPORTED_TITLE}>{REPORTED_LABEL}</span>
        One of {match.candidates.length} identical calls made at once
      </span>
    );
  }
  return (
    <span className="session-view__agent-call">
      <span className="session-view__reported" title={REPORTED_TITLE}>{REPORTED_LABEL}</span>
      {match.call.description && <span>{match.call.description}</span>}
      <code className="session-view__tool-use-id">{match.call.tool_use_id}</code>
    </span>
  );
}

// ProcessRows lists rows up to ROW_CAP, then offers the rest. A row holding a search hit or an alert is listed past the cap, since
// the command opened, or the search expanded it, to show that row.
function ProcessRows({ rows }: { readonly rows: SessionRow[] }) {
  const { hits, alertsByProcess } = useSessionRows();
  const [shown, setShown] = useState(ROW_CAP);
  const listed = rows.filter((r, i) => i < shown || containsHit(r, hits) || containsProcess(r, alertsByProcess));
  const rest = rows.length - listed.length;
  return (
    <ul className="session-view__rows">
      {listed.map((r) => <ProcessRow key={r.node.id} listed={r} />)}
      {rest > 0 && (
        <li>
          <Button variant="text-link" onClick={() => { setShown(rows.length); }}>
            Show {plural(rest, "more process", "more processes")}
          </Button>
        </li>
      )}
    </ul>
  );
}

function ProcessRow({ listed }: { readonly listed: SessionRow }) {
  const { alertsByProcess, hits, selectedId, onSelect } = useSessionRows();
  const { node, children, uidChange, folded, inferred, service, agent, own } = listed;
  const span = folded ? forkSpan(listed) : null;
  const rowClass = `session-view__row${hits.rows.has(listed) ? " session-view__row--hit" : ""}`;
  return (
    <li>
      <div className={rowClass}>
        <button
          type="button"
          className="session-view__name"
          aria-pressed={selectedId === node.id}
          onClick={() => { onSelect(node); }}
        >
          {executableName(node.path)}
        </button>
        <span className="session-view__mono session-view__cmdline">{commandLine(node.path, node.args)}</span>
        {agent && <Badge variant="info">agent</Badge>}
        {own && (
          <span title={OWN_TITLE}>
            <Badge variant="neutral">agent's own</Badge>
          </span>
        )}
        {folded && <Badge variant="neutral">{`×${String(folded.length + 1)}`}</Badge>}
        <span className="session-view__meta">
          {span
            ? `${formatNs(span.firstNs)} to ${formatNs(span.lastNs)}`
            : `pid ${String(node.pid)} · ${formatNs(node.fork_time_ns)}`}
          {node.exit_code !== undefined && node.exit_reason === "event" ? ` · exit ${String(node.exit_code)}` : ""}
        </span>
        {inferred && (
          <span title={INFERRED_LAUNCH_TITLE}>
            <Badge variant="info">inferred launch</Badge>
          </span>
        )}
        {service && (
          <span title={SERVICE_TITLE}>
            <Badge variant="info">service</Badge>
          </span>
        )}
        {/* A double fork or nohup left it to launchd (issue #1280); it is still listed under the process that created it. */}
        {node.reparented && (
          <span title={REPARENTED_TITLE}>
            <Badge variant="neutral">reparented, ppid 1</Badge>
          </span>
        )}
        {uidChange && (
          <span title={`Runs as uid ${String(uidChange.to)}; its creator ran as uid ${String(uidChange.from)}`}>
            <Badge variant="high">{uidChange.to === 0 ? "runs as root" : `runs as uid ${String(uidChange.to)}`}</Badge>
          </span>
        )}
        {(alertsByProcess.get(node.id) ?? []).map((alert) => (
          <span key={alert.id} className="session-view__alert">
            <Link to={`/alerts/${String(alert.id)}`}>
              <Badge variant={severityBadgeVariant(alert.severity)}>{alert.title}</Badge>
            </Link>
            {/* A vendored rule's match owes its author the credit on every surface that shows it (issue #765). */}
            {alert.origin && <span className="session-view__meta">{alert.origin}</span>}
          </span>
        ))}
      </div>
      {children.length > 0 && <ProcessRows rows={children} />}
    </li>
  );
}

// timelineHref opens a process's events in its host's timeline, on a window ending just after its last observed activity, so its exec
// and anything it did after are inside the window.
function timelineHref(hostId: string, node: ProcessNode): string {
  const atMs = Math.floor(lastActivityNs(node) / NANOSECONDS_PER_MILLISECOND) + 1;
  return `/hosts/${encodeURIComponent(hostId)}?view=timeline&pid=${String(node.pid)}&at=${String(atMs)}`;
}

// hostHref opens a process in its host's graph, selected and anchored at its fork time: the graph's ?process= takes the row id.
function hostHref(hostId: string, processId: number, forkNs: number): string {
  const atMs = Math.floor(forkNs / NANOSECONDS_PER_MILLISECOND) + 1;
  return `/hosts/${encodeURIComponent(hostId)}?process=${String(processId)}&at=${String(atMs)}`;
}
