// HostDetail is the response from GET /api/hosts/{host_id}: the identity + liveness view the host page header renders (issue #579).
// Extends the list row with the identity fields the enrollment row carries (kept fresh by the agent's inventory check-in; empty
// strings mean never enrolled or source unavailable). enrolled_at_ns / inventory_reported_at_ns are UnixNano (0 = never).
export interface HostDetail extends HostSummary {
  os_name: string;
  os_build: string;
  agent_version: string;
  source_ip: string;
  enrolled_at_ns: number;
  inventory_reported_at_ns: number;
}

export interface HostSummary {
  host_id: string;
  // hostname + os_version come from the endpoint enrollment row joined into the
  // hosts summary. The server always sends them (COALESCE to ""), so they are
  // required, not optional: an un-enrolled host carries empty strings, and the
  // UI falls back to host_id / a placeholder dash on the empty value.
  hostname: string;
  os_version: string;
  // platform is the host's operating system (darwin | windows | linux), from the enrollment row joined into the hosts summary. The
  // server always sends it (COALESCE to ""); an un-enrolled host carries an empty string, which the UI renders as "unknown". See
  // formatPlatform in HostList.
  platform: string;
  event_count: number;
  last_seen_ns: number;
  // overall_status is the server-computed agent-health rollup (issue #359): healthy | degraded | unhealthy | unknown. The server always
  // sends it (COALESCE to "unknown" for a host that has never posted a status snapshot), so it is required, like hostname. It drives the
  // Hosts-list health badge, distinct from the online/offline pill derived from last_seen_ns.
  overall_status: string;
}

// ComponentHealth is one condition in a host's agent-health snapshot, mirroring the server's per-component shape. type and reason are
// open vocabularies (a future signal needs no UI change); status is the same closed set as HostSummary.overall_status.
export interface ComponentHealth {
  type: string;
  status: string;
  reason?: string;
  message?: string;
  last_transition_ns: number;
}

// HostHealth is the response from GET /api/hosts/{host_id}/health: the rollup, the agent-stamped snapshot time, and the full component
// conditions. A host with no snapshot yields overall_status "unknown" and null components.
export interface HostHealth {
  overall_status: string;
  reported_at_ns: number;
  components: ComponentHealth[] | null;
  // derived_components are conditions the SERVER concluded, not ones the agent reported (issue #677): a telemetry stream this host
  // does use has gone silent while the agent's own health claims everything is fine. They are a separate field because they
  // contradict the agent's report, and overall_status above already folds them in. Null when the server has nothing to add. These
  // carry last_transition_ns 0: absence has no observed transition instant, so the UI must not render an age for them.
  derived_components: ComponentHealth[] | null;
  // episodes are the host's recorded sensor faults that needed a person (issue #778): open ones first, newest first, then the most
  // recent resolved ones. Always an array. NOT folded into overall_status, which says whether the host is healthy now; while a fault
  // is live its component already reports unhealthy, so the rollup already shows it, and an episode that can never close (recorded by
  // an agent too old to name its component) would otherwise leave a recovered host looking broken forever.
  episodes: HostHealthEpisode[];
}

// HostHealthEpisode is one recorded sensor fault: when it began on the host and, once it has, when it ended. Both instants are
// host-observed, so resolved_at_ns minus opened_at_ns is the outage.
export interface HostHealthEpisode {
  id: number;
  kind: string;
  component: string;
  // subject is the part of the component at fault (for a capture-provider failure, the provider). Absent when the fault concerns
  // the component as a whole.
  subject?: string;
  severity: string;
  title: string;
  description?: string;
  // detail is the fault's own fields, shaped by kind. For self_heal_failed: provider, outcome, attempts.
  detail?: Record<string, unknown> | null;
  opened_at_ns: number;
  // Absent while the fault is still in effect.
  resolved_at_ns?: number;
}

// Note: nanosecond timestamp fields (fork_time_ns, etc.) may lose precision
// beyond Number.MAX_SAFE_INTEGER (~9.007e15 ns ≈ ~104 days from epoch).
// Current wall-clock nanoseconds (~1.7e18) exceed this limit. The timestamps
// are still usable for display (ms-level precision is preserved) and for
// passing back to the API as opaque values, but arithmetic on them may be
// slightly imprecise. If exact ns precision is needed, switch to string
// representation.
// CodeSigning mirrors the wire's code_signing object (schema/events.json): the raw ESF identifiers plus the kernel CS_* flags
// bitmask. The extension omits the whole block when both identifiers are absent, so a missing block on an EXEC'D process means
// "unsigned". A fork-only process (no exec yet) also has no block because it runs its parent's inherited image; that absence is not
// an unsigned conviction, and verdict call sites must gate on exec_time_ns (see deriveSigningVerdict's callers).
export interface CodeSigning {
  team_id: string;
  signing_id: string;
  flags: number;
  is_platform_binary: boolean;
}

// LaunchdJob is one job definition a launchctl exec loaded: the plist it came from, the job's label, and what it runs. truncated is
// set when a field was cut to the agent's bounds.
export interface LaunchdJob {
  plist_path: string;
  label?: string;
  program?: string;
  program_arguments?: string[];
  truncated?: boolean;
}

export interface Process {
  id: number;
  host_id: string;
  pid: number;
  ppid: number;
  path: string;
  args?: string[];
  uid?: number;
  gid?: number;
  code_signing?: CodeSigning;
  sha256?: string;
  // cdhash is the 40-hex SHA-1 of the code directory, present for Hardened-Runtime binaries only.
  cdhash?: string;
  // pidversion is the kernel pid generation (audit_token_to_pidversion), present when the exec/fork event carried it. With pid it
  // uniquely identifies a process generation across PID reuse; the timeline's alert-chain scope keys on the (pid, pidversion) pair.
  pidversion?: number;
  fork_time_ns: number;
  exec_time_ns?: number;
  exit_time_ns?: number;
  exit_code?: number;
  // exit_reason distinguishes observed exits ("event")
  // from synthesized ones: "ttl_reconciliation" (server-side TTL force-grey),
  // "pid_reuse" (closed by an incoming fork on the same PID), "reexec"
  // (superseded by a re-exec on the same PID, see ReExecChain), or
  // "host_reconciled" (agent-side kill(pid,0) confirmed the PID is gone).
  // previous_exec_id links back to the prior generation in a same-pid
  // re-exec chain.
  exit_reason?: "event" | "ttl_reconciliation" | "pid_reuse" | "reexec" | "host_reconciled";
  previous_exec_id?: number;
  // Lineage (issue #1280). parent_process_id is the id of the creator's row, which the server links the tree by; parent_pidversion
  // is the creator's generation. The rest is what the exec reported: original_ppid is the creator's pid, which survives
  // reparenting, and reparented marks a process launchd adopted. Each is absent when the agent did not send it.
  parent_process_id?: number;
  parent_pidversion?: number;
  original_ppid?: number;
  responsible_pid?: number;
  responsible_pidversion?: number;
  session_id?: number;
  group_id?: number;
  tty?: string;
  start_time_ns?: number;
  cwd?: string;
  reparented?: boolean;
  // launchd_jobs are the job definitions a `launchctl load|bootstrap` exec loaded (issue #1341), as the agent read them from each
  // plist. Absent for any other exec.
  launchd_jobs?: LaunchdJob[];
  // AI agent attribution (issue #1281). agent_session_id names the session an exec's markers stamped or the row inherited from its
  // creator, with the agent's name and version. tool_call_group keys the agent tool call that started the process, and story_root_id
  // is the row of its nearest ancestor launchd started. Each is absent outside an agent session or when the chain was not seen.
  agent_session_id?: string;
  agent_name?: string;
  agent_version?: string;
  tool_call_group?: number;
  story_root_id?: number;
}

// ProcessSearchResult is the response from GET /api/search/processes (issue #582): a page of matching processes across all hosts,
// the opaque keyset cursor for the next page (absent on the last), and the full match count independent of the page.
export interface ProcessSearchResult {
  rows: Process[];
  next_cursor?: string;
  total_matched: number;
}

// AgentSessionSummary is one row of GET /api/agent-sessions (issue #1283): an AI agent session on one host, with the project it worked
// in (the working directory of its earliest tool call), when it was active, and how many retained processes and alerts it has.
export interface AgentSessionSummary {
  host_id: string;
  agent_session_id: string;
  agent_name: string;
  agent_version?: string;
  agent_pid?: number;
  cwd?: string;
  first_seen_ns: number;
  last_seen_ns: number;
  process_count: number;
  alert_count: number;
}

// AgentSessionResult is one page of the sessions list, most recently active first, with the keyset cursor for the next page (absent
// on the last) and the number of sessions the filter matched.
export interface AgentSessionResult {
  rows: AgentSessionSummary[];
  next_cursor?: string;
  total_matched: number;
}

// ActivityRow is what every row of an activity rollup shares (issue #1285): the process generation that touched the artifact, how many
// times, and when it first and last did.
export interface ActivityRow {
  pid: number;
  pidversion: number;
  count: number;
  first_ns: number;
  last_ns: number;
}

export interface FileActivityRow extends ActivityRow {
  // A watched-path event's type, or an AI agent's file operation (issue #1287).
  operation: "open" | "file_rename" | "file_truncate" | "file_delete" | FileOperation;
  path: string;
  source_path?: string;
  // Set when path is a directory standing for the agent file activity under it, folded by the extension.
  rolled_up?: boolean;
}

export interface NetworkActivityRow extends ActivityRow {
  remote_address: string;
  remote_port: number;
  protocol: string;
  remote_hostname?: string;
}

export interface DNSActivityRow extends ActivityRow {
  query_name: string;
  addresses: string[];
}

// ActivityClass is one class's totals and capped list: events counts its events (a coalesced one as the occurrences it stands for),
// distinct its distinct artifacts, and truncated says the list holds fewer rows than the class has.
export interface ActivityClass<Row> {
  events: number;
  distinct: number;
  truncated: boolean;
  rows: Row[];
}

// ActivityScope says how far an activity read's scope reached. When applied is false the activity is empty, never the host's.
export interface ActivityScope {
  applied: boolean;
  processes: number;
  unmatched: number;
  truncated: boolean;
}

// AgentToolCall is one tool call an AI agent session recorded in its transcript (issue #1288).
export interface AgentToolCall {
  tool_use_id: string;
  tool_name: string;
  command?: string;
  description?: string;
  file_path?: string;
  sidechain?: boolean;
  // truncated marks a command cut to the agent's 8 KiB limit.
  truncated?: boolean;
  called_at_ns: number;
  // uid owns the transcript the call was read from; a call is trusted only for that user's processes.
  uid: number;
}

export interface AgentToolCallsResponse {
  tool_calls: AgentToolCall[];
  truncated: boolean;
}

// AgentSessionLineage is a session's place among the sessions forked from each other on its host (issue #1347): the session it was
// forked from, if any, and the sessions forked from it.
export interface AgentSessionLineage {
  forked_from_session_id?: string;
  forked_session_ids: string[];
}

// ActivityResponse is GET /api/hosts/{id}/activity: what a process, its subtree or a session touched, with the scope's processes
// so a row's (pid, pidversion) can be named.
export interface ActivityResponse {
  files: ActivityClass<FileActivityRow>;
  network: ActivityClass<NetworkActivityRow>;
  dns: ActivityClass<DNSActivityRow>;
  scope: ActivityScope;
  processes: { id: number; pid: number; pidversion: number; path: string }[];
}

// EventSearchResult is the response from the fleet-wide connection and DNS search endpoints (GET /api/search/connections and
// /api/search/dns, issue #582): a page of matching events across all hosts, the opaque keyset cursor for the next page (absent on the
// last), and the full match count independent of the page. Each event carries the visibility Event shape (see EventRecord).
export interface EventSearchResult {
  events: EventRecord[];
  next_cursor?: string;
  total_matched: number;
}

// TimelineScope is the host timeline's report on a scoped read (issue #1282): the server resolved the scope itself, and says how far
// the events reflect it.
export interface TimelineScope {
  // At least one of the scope's processes carries a generation, so the events are narrowed to the scope. False means the events are
  // the whole host's, and processes says why: 0 means the scope named nothing stored.
  applied: boolean;
  processes: number;
  // Processes in the scope with no generation: their events cannot be selected, so an applied scope is missing them.
  unmatched: number;
  // The scope had more processes than the timeline reads, so the events reflect part of it.
  truncated: boolean;
}

// HostTimelineResult is a timeline page, with the scope report when the read was scoped.
export interface HostTimelineResult extends EventSearchResult {
  scope?: TimelineScope;
}

export interface ProcessNode extends Process {
  children?: ProcessNode[];
  network_connections?: EventRecord[];
  dns_queries?: EventRecord[];
  // Present when the server collapsed a group of identical-path sibling processes into this node (issue #416). The node then renders
  // as a "×N" badge instead of a single process; the embedded Process fields describe the earliest member (a representative), and
  // `aggregated` carries the group's cardinality, exited/running split, fork-time span, and a capped sample the UI expands in place.
  aggregated?: AggregatedSiblings;
  // UI-only annotation: when a subtree is collapsed or a system-path group is hidden,
  // the count of descendants that were dropped is stashed here so the renderer can
  // show a "+N" affordance on the surviving parent.
  _collapsedCount?: number;
}

// AggregatedSiblings mirrors the server's sibling-aggregation summary (issue #416). count is the full group size; exited_count and
// running_count partition it; first_fork_ns / last_fork_ns bound the fork-time span; sample is a capped, fork-ordered slice of the
// underlying members the UI materializes as children when the analyst expands the node.
export interface AggregatedSiblings {
  count: number;
  exited_count: number;
  running_count: number;
  first_fork_ns: number;
  last_fork_ns: number;
  sample?: ProcessNode[];
}

// ActivityHistogram is the response from GET /api/hosts/{host_id}/activity-histogram (issue #581): process-start counts per
// server-derived time bucket. buckets is sparse (empty buckets are omitted); total is the sum of counts.
export interface ActivityHistogram {
  bucket_ns: number;
  total: number;
  buckets: ActivityBucket[] | null;
}

export interface ActivityBucket {
  start_ns: number;
  count: number;
}

export interface EventRecord {
  event_id: string;
  host_id: string;
  timestamp_ns: number;
  event_type: string;
  payload: NetworkConnectPayload | DNSQueryPayload | ExecPayload | FileActivityPayload;
}

// ExecPayload is the payload of an exec event, surfaced in the host timeline (issue #583). Every timeline payload shares pid and an
// optional path, so the union members can be read for those two without narrowing; exec-specific fields (args, cwd) need a cast.
export interface ExecPayload {
  pid: number;
  ppid?: number;
  path?: string;
  args?: string[];
  cwd?: string;
  uid?: number;
  gid?: number;
}

export interface NetworkConnectPayload {
  pid: number;
  path?: string;
  uid?: number;
  protocol: string;
  direction: string;
  local_address?: string;
  local_port?: number;
  remote_address: string;
  remote_port: number;
  remote_hostname?: string;
}

// A connect is to a Unix-domain socket, the request to the daemon that serves it (issue #1355).
export type FileOperation = "create" | "modify" | "rename" | "delete" | "connect";

// FileActivityPayload is an AI agent's file activity as the extension folded it (issue #1287): one or more operations by one process.
export interface FileActivityPayload {
  pid: number;
  pidversion: number;
  operation: FileOperation;
  path: string;
  source_path?: string;
  coalesced_count?: number;
  last_timestamp_ns?: number;
  rolled_up?: boolean;
}

export interface DNSQueryPayload {
  pid: number;
  path?: string;
  uid?: number;
  query_name: string;
  query_type: string;
  response_addresses?: string[];
  protocol?: string;
}

export interface ProcessDetail {
  process: Process;
  network_connections: EventRecord[];
  dns_queries: EventRecord[];
  // Oldest-first list of prior exec generations on the same PID, populated
  // when a process called execve() more than once without forking in
  // between (e.g. shell exec-optimization chains). Empty for the common
  // single-exec case. See server/store/process.go GetExecChain.
  re_exec_chain?: Process[];
  // True when the server's row cap dropped flows, so the two lists above are a prefix of what this generation produced rather than
  // all of it. Reported by the server because the client never learns the cap; an absent flow must not read as one that never
  // happened. Optional so a response from an older server parses.
  flows_truncated?: boolean;
}

// ProcessLink is an edge between two process rows that parentage does not hold. inferred_launch links an open or launchctl exec to the
// process launchd started for it, inferred from timing and target rather than lineage (issue #1286). responsible_process links an app
// to a process launchd started that names the app as responsible, such as an XPC service it asked for (issue #1340).
export interface ProcessLink {
  from: number;
  to: number;
  kind: "inferred_launch" | "responsible_process";
}

// TreeResponse is the response from GET /api/hosts/{host_id}/tree: the forest plus the metadata that lets the page say what it is
// NOT showing (issue #423). returned counts the process rows the server's limit admitted, before sibling aggregation folded any of
// them into "×N" nodes; total_matched counts rows overlapping the window, independent of the ROW limit but bounded by the server's
// own counting bound; total_matched_capped reports that it stopped at that bound, so the number is a floor rather than a total;
// truncated reports whether the limit dropped rows.
//
// Both counts come from the server rather than being derived here, because both client-side derivations are wrong in the cases that
// matter: the handler clamps the requested limit, so the limit this client sent is not reliably the effective one, and counting
// rendered nodes undercounts because aggregation collapses siblings.
export interface TreeResponse {
  roots: ProcessNode[];
  // links are the read's inferred launches; absent when there are none.
  links?: ProcessLink[];
  returned: number;
  total_matched: number;
  total_matched_capped: boolean;
  truncated: boolean;
  // retained_from_ns is the moment before which completed process records were deleted by retention (issue #1153). Absent when
  // retention is disabled, or from a server that predates the field.
  retained_from_ns?: number;
  // agents are a session read's AI agent processes (issue #1334): the agent carries no session marker, so it is not among the roots,
  // and each root it created names it by parent_process_id. Absent for other reads, and when the agent was not seen.
  agents?: ProcessNode[];
  // agent_own_truncated is set when an agent's own processes, the children of an agents node (issue #1361), were cut at their bound.
  agent_own_truncated?: boolean;
}

export interface Alert {
  id: number;
  host_id: string;
  rule_id: string;
  // source is "detection" for catalog-rule findings and
  // "application_control" for blocks emitted by the extension's
  // AUTH_EXEC decision walker. Surfaced so the UI can chip / filter
  // alerts by subsystem without re-parsing rule_id. Distinct from
  // `origin` below, which names the rule's AUTHOR rather than the
  // subsystem that raised the alert.
  source: string;
  severity: string;
  title: string;
  description: string;
  // origin credits whoever wrote the rule that fired: "Fleet EDR" for a rule
  // this project authored, "Locally authored" for one written on this
  // deployment, and "SigmaHQ, by <author>" for one from the imported corpus. Captured when the alert was raised rather than looked up from
  // today's catalog, so it stays correct for a rule that has since changed or
  // been removed.
  //
  // The imported corpus ships under the Detection Rule License, which requires
  // the author be credited wherever a match is displayed, so a surface showing
  // an alert must render this. Optional because a server predating the field
  // omits it, and alerts raised before the column existed carry an empty
  // string; a renderer must handle both by showing nothing rather than by
  // inventing a credit.
  origin?: string;
  // techniques are the MITRE ATT&CK ids the rule maps to (e.g. ["T1543.004"]). Omitted by the server when the rule
  // declares none, so optional here.
  techniques?: string[];
  process_id: number;
  status: string;
  // disposition is "monitor" for a monitor record (issue #994): a match from a rule in monitor mode, kept so it can be read before the
  // rule is promoted. It is not an alert: it is never notified and cannot be triaged, so a surface showing one must not offer triage.
  // Optional because a server predating the field omits it, which means every row it serves is an alert.
  disposition?: "alert" | "monitor";
  created_at: string;
  updated_at: string;
  resolved_at?: string;
}

export interface AlertDetail extends Alert {
  event_ids: string[];
}

// ContainmentDelivery mirrors server/response/api.ContainmentDelivery: a host's latest set_network_containment command, and whether it
// carries the host's current state.
export interface ContainmentDelivery {
  command_id: number;
  status: string;
  result?: Record<string, unknown>;
  current: boolean;
}

// ContainmentState mirrors server/response/api.ContainmentState: a host's desired network containment (#948). A host never contained
// is version 0 with no delivery.
export interface ContainmentState {
  host_id: string;
  contained: boolean;
  version: number;
  epoch: number;
  reason?: string;
  updated_by?: string;
  updated_at?: string;
  delivery?: ContainmentDelivery;
}

// ReachableAddress mirrors server/response/api.ReachableAddress: one destination a contained host may still reach (#1059). The
// note is the operator's own name for it, kept for the console and the audit trail; it is not sent to the host.
export interface ReachableAddress {
  cidr: string;
  port?: number;
  transport?: "tcp" | "udp";
  note?: string;
}

// ReachableSet mirrors server/response/api.ReachableSet: the whole set at one version. Version 0 is the empty set a deployment
// starts with, which is containment's own lifeline and nothing more.
export interface ReachableSet {
  version: number;
  addresses: ReachableAddress[];
  updated_at?: string;
  updated_by?: string;
  // updated_by_label is the display label the server resolves from updated_by at read time, absent when it cannot be resolved
  // (a deleted user or service account), in which case the console falls back to the raw principal id.
  updated_by_label?: string;
}

// ContainmentChange mirrors server/response/api.ContainmentChange: the state after a change request and the command queued for it.
export interface ContainmentChange {
  state: ContainmentState;
  changed: boolean;
  command_id?: number;
}

export interface Command {
  id: number;
  host_id: string;
  command_type: string;
  payload: Record<string, unknown>;
  status: string;
  created_at: string;
  acked_at?: string;
  completed_at?: string;
  result?: Record<string, unknown>;
}

// ApplicationControlPolicy mirrors server/rules/api.ApplicationControlPolicy.
// The demo cut shows a single Default policy; multi-policy support is
// post-demo. Rules is populated by the GET /policies/{id} endpoint and
// omitted from the list response, so the field is optional.
export interface ApplicationControlPolicy {
  id: number;
  name: string;
  description: string;
  version: number;
  default_action: string;
  created_at: string;
  updated_at: string;
  created_by: string;
  updated_by: string;
  // assignment_count is the number of host_groups the policy is assigned to. Server-decorated via a correlated COUNT
  // subquery on app_control_assignments so the PoliciesList view can render "N host groups" without an N+1 round trip.
  // The seeded Default policy starts at 1 (its assignment to all-hosts); policies created via the create endpoint start
  // at 0 and grow as Phase B opens up multi-group assignment editing. The UI handles 0/1/N as singular/plural/zero labels.
  assignment_count: number;
  // rule_count is every rule attached to the policy, enabled or not. Server-decorated the same way as assignment_count, so
  // the policies list can say what a policy holds without fetching each policy's rules.
  rule_count: number;
  rules?: ApplicationControlRule[];
}

// ApplicationControlRule mirrors server/rules/api.ApplicationControlRule.
// `rule_type` is BINARY in the demo cut; the other five values exist on the
// schema's ENUM but the create handler rejects them until their validators
// ship. custom_msg / custom_url are operator-authored optional strings; the
// host-app modal renders custom_msg verbatim and "More info" links for
// http/https custom_urls.
export interface ApplicationControlRule {
  id: number;
  policy_id: number;
  rule_type: string;
  identifier: string;
  action: string;
  enforcement: string;
  enabled: boolean;
  severity: string;
  source: string;
  source_ref?: string;
  custom_msg?: string | null;
  custom_url?: string | null;
  comment?: string;
  expires_at?: string | null;
  created_at: string;
  updated_at: string;
  created_by: string;
}
