## Why

The host detail page titles itself with the raw host id and shows none of the identity the server now keeps fresh: hostname, OS name/version/build, agent version, last seen, source IP, event count, or enrollment date. Every comparable EDR presents this context on the host page, and PR 1 of #579 (the inventory check-in, merged) made the data trustworthy. This is PR 2 of #579 (epic #577): the read endpoint plus the header UI.

## What Changes

- New operator endpoint `GET /api/hosts/{host_id}` returning one host's identity + liveness: host id, enrollment hostname, OS name/version/build, agent version, source IP, enrolled-at, inventory-reported-at, last-seen, event count, and the agent-health rollup. 404 for an unknown host id; a host that never enrolled still returns with empty identity fields (matching the list endpoint's posture).
- The host detail page (`/hosts/:hostId`) gains an identity header: hostname as the title (falling back to the host id), an identity/liveness meta row, and a copyable raw host id. The existing agent-health panel stays below it.
- Header data loads best-effort: a fetch failure degrades to the current raw-id title rather than blocking the process tree.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `server-rest-api`: new host detail endpoint requirement (ADDED).
- `web-ui`: new host detail header requirement (ADDED).

## Impact

- `server/detection/api/types.go` (HostDetail), `server/detection/internal/mysql/hosts.go` (single-host join), `server/detection/internal/operator/` (new handler file mirroring the host-health seam), detection bootstrap wiring.
- `ui/src/types.ts`, `ui/src/api.ts`, new `ui/src/components/HostHeader.tsx` (+ test + styles), `ui/src/components/ProcessTree.tsx` integration.
- No agent or wire changes; reads tables PR 1 already populates.
