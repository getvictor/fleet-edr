## Why

Today the UI renders every navigation tab and every action control to every authenticated operator,
regardless of what their role permits. The wave-1 authorization chokepoint correctly denies an
unpermitted action server-side, but the operator only finds out by clicking: a JIT-provisioned
`analyst` who opens Application control sees a raw `Error: API error: 403`, and the Kill process /
isolate / run-script controls are shown to roles that cannot use them. That is a least-privilege
console that neither looks nor feels least-privilege - a UX and credibility gap against the
security-console set (CrowdStrike Falcon, SentinelOne Singularity, Microsoft Defender for Endpoint),
all of which hide what a role cannot do.

The fix has two halves: (1) tell the UI what the operator is allowed to do, and (2) have the UI hide
affordances it cannot use and degrade gracefully when the server denies anyway. The server stays the
only enforcement point; this change is purely additive UX on top of the existing chokepoint. The
build-versus-library decision and the rationale for shipping permissions rather than roles are
recorded in ADR-0012.

## What Changes

- The session-probe response (`GET /api/session`) gains the operator's **effective permission set**:
  the flat list of action identifiers the operator is permitted, computed server-side as the union of
  the active session's role-binding grants with the `super_admin` wildcard expanded against the action
  registry. SSO and break-glass sessions both carry it. The wire never ships a wildcard token.
- The UI hides navigation entries whose gating read action is absent from the permission set (for
  example, Application control is hidden without `application_control.read`) and hides action controls
  whose action is not granted (for example, Kill process is hidden without `host.kill_process`). Gating
  is derived solely from the server-provided set; the UI holds no role→action mapping of its own.
- The UI treats an authorization denial it did not anticipate as a graceful no-access state - a
  human-readable message plus a refetch of the permission set - never a raw `API error: 403`. This
  covers the snapshot-staleness window (a role changed mid-session) and any affordance not yet gated.
- No change to the authorization chokepoint, the role / action registry, or the persisted
  authorization model. The permission set is advisory to the UI; the server remains authoritative for
  every action.

## Capabilities

### Modified Capabilities

- `ui-authentication-session`: the current-user / session-probe response is extended to include the
  operator's effective permission set, so the UI can discover not just *who* is logged in but *what
  they may do*, without a per-affordance round trip. The set is advisory and is never authorization in
  itself.
- `web-ui`: navigation entries and action affordances become capability-gated - hidden when the
  operator's permission set does not include the relevant action - and authorization denials degrade to
  a graceful no-access state instead of a raw transport error.

No new capabilities are introduced and no other context's behavior changes.

## Impact

**API surface:** one additive field on the `GET /api/session` response body (a list of action
identifiers). No new endpoint; no change to request shapes, status codes, or the cookie / CSRF
contract.

**Server:** the effective permission set is computed from the same role bindings the authorization
chokepoint already loads to build the request actor, so there is no new persisted state and no new
cross-request in-process state (consistent with ADR-0010). The `*` wildcard is expanded against the
existing action registry so the wire never carries `*`.

**UI:** a single capability seam (a permission-set provider plus one check) consumed by the navigation
and the affordance-bearing surfaces (host list navigation, process detail, alert lifecycle controls,
application control). The implementation is bespoke and dependency-free per ADR-0012.

**Security:** enforcement is unchanged. UI gating is non-authoritative; the chokepoint still denies
every unpermitted action and the spec mandates the UI keep handling `403`. Hiding an affordance is
never relied on as a control, so an absent or stale permission set can change only what is *shown*,
never what is *allowed*.

**Out of scope / deferred:** per-resource (`host_group` / `host`) scoped gating, which depends on
wave-2 scoped role bindings; live mid-session permission push; any client-side evaluation of
authorization conditions (ADR-0012 records the trigger for revisiting a client authorization library).

**Rollback:** the change is additive and reversible. Reverting the UI restores unconditional rendering;
reverting the server field leaves the UI to treat an absent permission set as "gate nothing", which is
safe because the server still enforces - fail-open affects *visibility* only, never access. The agent
protocol, the events schema, and the persisted host token are untouched, so no agent-side rollback
steps apply.
