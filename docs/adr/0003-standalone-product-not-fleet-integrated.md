# 0003. EDR is a standalone product; Fleet is a deployment channel

- Status: Accepted
- Date: 2026-04-18
- Deciders: getvictor

## Context

An EDR that sits next to Fleet (the MDM + osquery platform) can be built in
several shapes. Two extremes frame the design space:

1. **Tightly integrated**: the EDR data plane lives inside Fleet. The agent
   is an osquery extension or a new Fleet daemon. The UI is a tab in Fleet's
   web app. The server is a Fleet-team-owned service sharing Fleet's DB,
   auth, and API. Microsoft Defender for Endpoint inside the Microsoft
   365 / Intune ecosystem is the canonical example: same identity (Entra),
   same admin console (Defender XDR), MDE telemetry feeds Intune compliance
   policies, and Intune enforcement is gated on EDR posture.
2. **Standalone product with a thin deployment contract**: the EDR ships its
   own server, agent, UI, and installer. It runs on its own, talks to its
   own database, and is usable without Fleet. Fleet (and other MDMs) are
   deployment channels that drop the signed `.pkg` onto endpoints and push a
   configuration profile that writes the enroll secret into a well-known
   path. Jamf Protect alongside Jamf Pro is the reference model: same
   vendor and same SSO, but separate consoles, separate agents on the
   endpoint, and separate data planes. Protect runs on hosts not managed
   by Pro, and Pro routinely deploys non-Jamf EDRs (CrowdStrike, MDE,
   SentinelOne) the same way it deploys Protect.

The forces:

- Customers manage endpoints with many MDMs: Jamf, Kandji, mosyle, Intune,
  and Fleet. A design that requires Fleet to run the EDR excludes every
  other MDM and cuts the addressable market by an order of magnitude.
- An EDR's detection surface, response API, and process-graph store have
  very different scaling + retention shapes than an MDM's host inventory +
  osquery schedule. Merging the two data planes means the EDR inherits
  Fleet's operational envelope (and vice versa) for no functional gain.
- Security buyers want to see independence between the EDR and the MDM --
  an MDM compromise should not automatically defeat the EDR, and vice
  versa. Tight integration makes that story harder to tell.
- The two products serve different audiences. Fleet's primary console is
  for IT / device-management teams: inventory, software install status,
  configuration drift, OS-update compliance. The EDR's primary console is
  for security / SOC teams: real-time alerts, process-tree investigation,
  blocklist response. Different RBAC needs, different alert-fatigue
  tolerances, different on-call rotations. A merged console either
  compromises one audience's workflow or accumulates feature flags to
  pretend it doesn't.
- Velocity isolation matters disproportionately for an early-stage
  product. The EDR is pre-MVP and is still discovering what its detection
  surface, response API, and operator workflow want to look like. Fleet
  is mature and has a slower QA + release cadence appropriate to a tool
  whose customers depend on it daily. Coupling the EDR to that cadence
  would slow every detection-rule change to a Fleet-release-window pace,
  while coupling Fleet to the EDR's churn would risk Fleet's stability
  reputation. Independent products let each team move at the rate its
  product needs.

## Decision

The EDR is a standalone product. It ships its own server (`fleet-edr-server`),
agent (`fleet-edr-agent`), UI (embedded in the server binary), and installer
(signed `.pkg`). It has its own database (MySQL), its own auth (session
cookies + CSRF for the UI, bearer tokens for agent-to-server), and its own
API at `/api/*`.

Fleet is one of several supported deployment channels. The contract between
Fleet and the EDR is deliberately thin and consists of three things the MDM
must do on the endpoint:

1. Deliver the signed `.pkg` via the MDM's package-management channel.
2. Push two `.mobileconfig` profiles (system extension allowlist and
   network extension allowlist) so the TCC prompts don't block the user.
3. Provision the enroll secret for the agent to read at startup. Today the
   agent reads `EDR_ENROLL_SECRET` from its environment (see
   `agent/config`); the MDM-owned LaunchDaemon plist that wraps the agent is
   where that env var lands. A future revision may switch to reading from a
   root-owned config file at `/etc/fleet-edr.conf` so the secret doesn't
   appear in `launchctl print` output, but that is an implementation choice
   inside the enroll-secret provisioning step, not a separate contract.

Jamf, Kandji, mosyle, and Intune use equivalent mechanisms. None of them are
privileged over the others in the EDR's design.

## Consequences

**Good:**

- The EDR is usable in any MDM environment (or none). The addressable
  market is every Mac-heavy shop running any MDM, not just Fleet customers.
- The two products can evolve independently. An EDR release doesn't need
  Fleet's release window, and Fleet's data-plane changes can't accidentally
  break EDR detection.
- The EDR server can be self-hosted by customers who don't want their EDR
  data leaving their perimeter, regardless of where their Fleet instance
  lives.
- Security story is cleaner: a compromise of the MDM does not
  automatically equal a compromise of the EDR.

**Bad:**

- Operators have two products to deploy and run. The deployment contract
  (signed `.pkg` + two profiles + the enroll-secret drop) is simple but
  still a non-zero integration cost per MDM.
- No shared host inventory. A customer running both Fleet and the EDR will
  see the same Mac from both consoles with separate host identifiers.
  Cross-linking (for lookups, not for data-plane merging) is a future
  consideration.
- The EDR must reimplement things Fleet already solves (auth, RBAC, audit
  logging, multi-tenant isolation) rather than reusing Fleet's
  implementations. Accepted cost for the decoupling it buys.

## Alternatives considered

**Tight integration into Fleet.** Rejected as above: cuts the addressable
market to Fleet customers only, couples release cadences, and merges two
operationally-different data planes for no product-side gain.

**EDR agent as an osquery extension or as part of `orbit`.** osquery
(the engine) and `orbit` (Fleet's launcher / wrapper around osquery,
distributed as `fleetd`) are both pull-based: a query is scheduled, the
engine evaluates it on a cadence, results are batched back. Rejected
for the EDR agent because:

- The detection surface needs **real-time** event streams, not periodic
  snapshots. Endpoint Security Framework (`NOTIFY_EXEC`, `NOTIFY_FORK`,
  `NOTIFY_EXIT`, `NOTIFY_OPEN`) and Network Extension's
  `NEFilterDataProvider` deliver events as they happen. Detection rules
  like `suspicious_exec` fire on a chain that completes in ~150ms; a
  60-300s osquery poll cycle drops the chain entirely.
- Several detections require **inline blocking**
  (`ES_AUTH_RESULT_DENY`), which only a system extension subscribed to
  ES auth events can do. osquery has no analogue.
- Telemetry **volume + back-pressure** match a streaming agent better
  than a query engine: a busy host generates thousands of exec events
  per minute, far past what `processes` table snapshots can capture.
- Detection logic riding as an osquery extension inherits osquery's
  update cadence (a fleetd / orbit release), which is too slow for
  security content that needs to ship the day a CVE drops.

Bundling the EDR agent into `orbit` (so Fleet customers get one daemon
to manage) would inherit all of the above plus tie EDR availability to
Fleet's daemon. The deployment-channel contract documented in this ADR
is the cleaner alternative: ship a standalone agent, and let any MDM
(Fleet included) drop the signed `.pkg` + profiles.

**EDR server as a Fleet plugin / server-side extension.** Rejected: would
tie the EDR server's availability and scaling profile to Fleet's, and
require a Fleet-flavoured auth model for the EDR's admin UI. Also closes off
customers who don't run Fleet.

## References

- Jamf Protect + Jamf Pro as the two-independent-products reference model.
