# 0012. Capability-based UI gating from a server-provided permission set

- Status: Accepted
- Date: 2026-06-01
- Deciders: getvictor

## Context

The current user-management work (issue #66) introduced an embedded OPA / Rego authorization chokepoint: every privileged UI/API handler calls the authorization decision before acting, and the seeded roles (`super_admin`, `admin`, `senior_analyst`, `analyst`, `auditor`) map to a fixed action registry. That boundary is sound, and it is the only thing that actually protects the system.

The UI knows nothing about it. `GET /api/session` returns only the user identity, the CSRF token, and the auth method. The React app therefore renders every navigation tab and every action control unconditionally. An operator whose role lacks an action discovers this only by clicking: a JIT-provisioned `analyst` who opens Application control gets a raw `Error: API error: 403`, and the Kill process control is shown to roles that cannot use it. That is poor UX, and for a product whose competitive set (CrowdStrike Falcon, SentinelOne, Microsoft Defender) ships polished least-privilege consoles, a credibility gap.

We want the UI to hide affordances an operator cannot use. To do that the frontend needs a reliable picture of the operator's effective permissions, and we must decide (a) how the frontend learns them and (b) whether to build a bespoke gating helper or adopt a client-side authorization library.

Two forces constrain the answer. First, the server already owns the authoritative role→action mapping (Rego + the action registry); any second copy of that logic is a drift hazard, and for a security product two policy definitions that can disagree is a liability, not a feature. Second, ADR-0010 (stateless server) requires that no UI-specific cross-request state live in process: whatever we hand the UI must be derivable per request from the session's role bindings, which is exactly how the chokepoint already builds the request actor.

## Decision

1. The server computes the authenticated operator's **effective permission set** (the union of the action grants across the session's role bindings, with the `super_admin` `*` wildcard expanded against the action registry) and returns it in the session-probe response (`GET /api/session`) as a flat list of action identifiers.
2. The UI gates navigation entries and action controls through a single centralized capability seam that reads that set. It ships **permissions (action identifiers), not role names**: the UI never maps roles to features.
3. We build that seam **bespoke** (a thin membership check over the permission set behind one capability boundary). We do **not** adopt a client-side authorization library for the current release.
4. The Rego authorization chokepoint remains the **sole** security boundary. UI gating is a usability layer only; the UI MUST still treat an unexpected `403` as a graceful no-access state, never a raw error.

## Consequences

What becomes easier:

- One vocabulary end to end. The action identifiers the UI checks are the same strings the chokepoint enforces and the same strings the audit log records (`authz.<action>`), so a UI gate maps 1:1 to a backend check and to an audit row. There is no role→feature translation table to drift.
- The raw-`403` UX defect is fixed by item 4 (graceful denial) independently of the hiding work.
- The seam is tiny, dependency-free, and reversible. Centralizing behind one boundary means swapping the implementation later (including adopting a library) is mechanical.
- Consistent with ADR-0010: the permission set is derived per request from the session's bindings; no new in-process shared state.

What becomes harder, and the costs:

- The permission set is a **session-lifetime snapshot**, so server enforcement and UI display update on different schedules: the chokepoint reads fresh bindings on the next request (enforced immediately), while the UI keeps showing the cached snapshot until the next login or an explicit refetch. That gap is the cost; it must be documented as a UI property and is mitigated by the refetch-on-denial self-heal below.
- The session response gains a field that must stay aligned with the action registry. The UI inherits correctness from the server because it only echoes server-computed data, but a new wire field is a new thing to keep honest.
- Bespoke means we own the gating code. The burden is near zero precisely because the UI holds no policy logic, but it is not zero.

## Alternatives considered

- **Ship the role name(s) and map role→features in the UI.** Attractive because the session already knows the role. Rejected: it duplicates the role→action policy in TypeScript, so every `roles.json` change needs a matching UI change or the two drift. Decision-as-data means shipping the computed result, not the inputs.
- **Coarse UI capability booleans** (`{canViewAppControl, canKillProcess, …}`). Attractive: smallest payload, leaks no taxonomy. Rejected as the primary shape because it introduces a _second_ permission vocabulary the server must maintain alongside the action registry (another drift surface) for no security benefit (our action catalog is checked into the repo and is not sensitive). The flat action list reuses the vocabulary we already have.
- **Adopt a client-side authorization library (e.g. CASL / `@casl/react`).** Attractive: ready-made conditional-render components, isomorphic rules, a well-trodden path. Rejected for the current release because it is a client-side _decision engine_ and we already have one on the server (Rego). Using it for real means reimplementing policy conditions in JS (drift; two engines that can disagree is unacceptable for a security product); using it only as a conditional-render wrapper over a flat set exercises a small fraction of the library that a thin bespoke check replaces. A future release with scoped bindings (`host_group` / `host`) may revisit this _only if_ the UI must evaluate resource/attribute conditions client-side without a server round-trip; the centralized seam makes that migration cheap.
- **Per-affordance authorization probe** (ask the chokepoint "can I?" for each control). Attractive: always fresh, no snapshot staleness. Rejected: chatty, and unnecessary for the current deployment-wide scopes where one session-bootstrap fetch covers every action. A probe pattern may return for per-resource (`host`-scoped) checks in a future release.

## References

- ADR-0010 (stateless server): the permission set is per-request-derived session data, not in-process state.
- OpenSpec change `add-capability-based-ui-gating` - the behavioral spec deltas for this decision.
- [`authz.md`](../authz.md): role / action matrix. `server/identity/internal/authz/policy/data/{actions,roles}.json` is the authoritative action registry and role grants.
- User-management plan, issue #66: the current identity boundary this builds on.
- Frontend RBAC guidance ("expose permissions, keep enforcement server-side"): CASL (https://github.com/stalniy/casl), LogRocket on access-control models for the frontend (https://blog.logrocket.com/choosing-best-access-control-model-frontend/), Oso on RBAC (https://www.osohq.com/learn/rbac-role-based-access-control).
