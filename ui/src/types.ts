export interface HostSummary {
  host_id: string;
  event_count: number;
  last_seen_ns: number;
}

// Note: nanosecond timestamp fields (fork_time_ns, etc.) may lose precision
// beyond Number.MAX_SAFE_INTEGER (~9.007e15 ns ≈ ~104 days from epoch).
// Current wall-clock nanoseconds (~1.7e18) exceed this limit. The timestamps
// are still usable for display (ms-level precision is preserved) and for
// passing back to the API as opaque values, but arithmetic on them may be
// slightly imprecise. If exact ns precision is needed, switch to string
// representation.
export interface Process {
  id: number;
  host_id: string;
  pid: number;
  ppid: number;
  path: string;
  args?: string[];
  uid?: number;
  gid?: number;
  code_signing?: {
    team_id: string;
    signing_id: string;
    flags: number;
    is_platform_binary: boolean;
  };
  sha256?: string;
  fork_time_ns: number;
  exec_time_ns?: number;
  exit_time_ns?: number;
  exit_code?: number;
  // exit_reason distinguishes observed exits ("event")
  // from synthesized ones: "ttl_reconciliation" (server-side TTL force-grey),
  // "pid_reuse" (closed by an incoming fork on the same PID), "reexec"
  // (superseded by a re-exec on the same PID - see ReExecChain), or
  // "host_reconciled" (agent-side kill(pid,0) confirmed the PID is gone).
  // previous_exec_id links back to the prior generation in a same-pid
  // re-exec chain.
  exit_reason?: "event" | "ttl_reconciliation" | "pid_reuse" | "reexec" | "host_reconciled";
  previous_exec_id?: number;
}

export interface ProcessNode extends Process {
  children?: ProcessNode[];
  network_connections?: EventRecord[];
  dns_queries?: EventRecord[];
  // UI-only annotation: when a subtree is collapsed or a system-path group is hidden,
  // the count of descendants that were dropped is stashed here so the renderer can
  // show a "+N" affordance on the surviving parent.
  _collapsedCount?: number;
}

export interface EventRecord {
  event_id: string;
  host_id: string;
  timestamp_ns: number;
  event_type: string;
  payload: NetworkConnectPayload | DNSQueryPayload;
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
  // Oldest-first list of prior exec generations on the same PID - populated
  // when a process called execve() more than once without forking in
  // between (e.g. shell exec-optimization chains). Empty for the common
  // single-exec case. See server/store/process.go GetExecChain.
  re_exec_chain?: Process[];
}

export interface TreeResponse {
  roots: ProcessNode[];
}

export interface Alert {
  id: number;
  host_id: string;
  rule_id: string;
  // source is "detection" for catalog-rule findings and
  // "application_control" for blocks emitted by the extension's
  // AUTH_EXEC decision walker. Surfaced so the UI can chip / filter
  // alerts by origin without re-parsing rule_id.
  source: string;
  severity: string;
  title: string;
  description: string;
  process_id: number;
  status: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
}

export interface AlertDetail extends Alert {
  event_ids: string[];
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
