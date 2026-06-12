# Best practices for Qodo review

Curated review guidance for this repo. Scope: invariants that linters and CI do not already enforce. Style and formatting are owned by golangci-lint, SwiftLint, Prettier, and dash-lint; do not raise them here.

## Security invariants

- Every IPC channel (XPC between extension, agent, and host app) validates the peer before acting: audit_token plus a code-signing requirement pinned to our team ID. A handler that processes a message before peer validation is a finding even if "the message looks harmless".
- Event payload fields must come from the kernel-vouched source. On macOS that means audit_token-derived PID, UID, and GID, never the userspace-claimed `es_process_t` fields. A diff that reads the claimed field where a vouched one exists is a finding.
- Endpoint Security callback threads never block on the network or on unbounded work. Any `SecStaticCodeCheckValidity` or code-signing evaluation on the ES path must pass `.noNetworkAccess`. A synchronous DNS lookup, HTTP call, or unbounded loop in an ES handler stalls the syscall for the whole machine.
- Authorization gates run before the side effect. In server handlers, `HTTPGate` (or the context's authz check) precedes the mutation; a code path that mutates then checks, or that returns early past the gate, is a finding.
- The `audit_events` table is append-only. Production code must never UPDATE or DELETE rows there, and the dual-emit (DB plus slog) must fire even when the INSERT fails.
- Secrets and tokens: enroll secrets and host tokens never appear in log statements, error strings, or HTTP responses. At-rest token files are 0600. Event payloads may include file paths, command lines, and URLs; logs may not include PII.
- Stateless server (ADR-0010): no new in-process map, channel, or queue that holds state a peer replica would need. Durable cross-request state goes in MySQL; per-request state may ride in signed cookies. A per-replica cache is acceptable only with an explicit "safe to lose" comment.

## Performance on hot paths

The hot paths are the ES event handlers in the extension, the agent's event queue and uploader, and the server's ingest endpoint down to the MySQL writes. On these paths:

- Per-event heap allocations matter. Prefer reuse (sync.Pool, preallocated buffers) over per-event allocation when the diff touches a loop that runs per event.
- Database access is batched. A query inside a per-event loop (N+1) is a finding; the ingest path writes batches in a single transaction.
- Lock scope is minimal. A mutex held across an I/O call on an ingest or callback path is a finding.
- Kernel-adjacent handlers bound their CPU and memory. Anything recursive or unbounded (walking process trees, scanning directories) needs an explicit depth or size cap.

## Correctness conventions

- Wire-format changes (new struct fields in the event envelope, batch encoding) ship with a property-based round-trip test (`Marshal` then `Unmarshal` equals identity, via `pgregory.net/rapid`). A new field without one is a gap.
- Error handling on the agent and server: errors from the queue, uploader, and store are handled or explicitly logged with context; a swallowed error on the ingest path hides data loss.
- Re-exec chains and process trees: code walking `previous_exec_id` or building process forests must terminate on cycles and missing parents; assume the input can be adversarial.
- When a symbol is deleted (function, type, command, XPC message kind, config field), every comment referencing it goes in the same diff. Stale references in IPC-adjacent comments are a recurring review defect in this repo.
