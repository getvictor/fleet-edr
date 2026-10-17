# Show the agent's own background processes in its sessions

## Why

A session view showed the processes stamped with the session and the agent process itself, but not what the agent ran for its own purposes. In the RSA rerun, Claude Code started 112 processes and 37 were the session's; the rest were plugin scans, shell snapshots, git status checks and its fork daemon (issue #1361).

## What changes

- A session's tree read returns, under each agent node, the agent's own descendants that carry no session marker, for the span it served the session, bounded and marked when cut.
- The Processes view counts them and lists them on request under the agent, each marked as the agent's own. Commands is unchanged.

## Impact

API: an agent node's `children` and `agent_own_truncated` on a session read. UI: a toggle in the Processes view.
