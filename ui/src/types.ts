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
  // Phase 7 additions. exit_reason distinguishes observed exits ("event")
  // from synthesized ones: "ttl_reconciliation" (server-side TTL force-grey),
  // "pid_reuse" (closed by an incoming fork on the same PID), "reexec"
  // (superseded by a re-exec on the same PID — see ReExecChain), or
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
  // Oldest-first list of prior exec generations on the same PID — populated
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
