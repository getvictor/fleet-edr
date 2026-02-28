export interface HostSummary {
  host_id: string;
  event_count: number;
  last_seen_ns: number;
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
}

export interface ProcessNode extends Process {
  children?: ProcessNode[];
  network_connections?: EventRecord[];
  dns_queries?: EventRecord[];
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
}

export interface TreeResponse {
  roots: ProcessNode[];
}
