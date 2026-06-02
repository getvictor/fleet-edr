## Phase 1: server permission set

- [ ] **1.1** Compute the effective permission set from the active session's role bindings: union of
  action grants at the deployment-wide scope, with the `super_admin` `*` wildcard expanded against the
  action registry. Reuse the binding load that session middleware already performs to build the request
  actor; add no new persisted or in-process state (ADR-0010).
- [ ] **1.2** Add the permission set as an additive field on the `GET /api/session` response body.
  Populate it for both SSO and break-glass sessions. Never serialize a wildcard token.
- [ ] **1.3** Per-context integration test in `server/identity/internal/tests/` covering every seeded
  role: an `analyst` session returns the analyst action set and omits `host.kill_process` /
  `application_control.read`; a `senior_analyst` session is a superset that includes them; `admin` and
  `auditor` sessions each return their respective seeded grants; a `super_admin` session returns the
  concrete action registry (wildcard expanded, no `*`); a logged-out probe still returns 401 with no
  permission set.

## Phase 2: UI capability seam

- [ ] **2.1** Add the new `permissions` field to the `SessionInfo` interface in `ui/src/api.ts` first
  (so the type is in place before consumers compile), then seed a permission-set provider from the
  existing session bootstrap and expose one check (`can(action)` / `<Can action="…">`). The UI holds no
  role→action mapping; it reads only the server-provided set.
- [ ] **2.2** Gate navigation entries on the read action for their destination (Application control on
  `application_control.read`, etc.).
- [ ] **2.3** Gate action controls on the action they perform: Kill process (`host.kill_process`),
  isolate (`host.isolate`), run script (`host.run_script`), and the alert lifecycle controls on their
  respective actions.
- [ ] **2.4** UI unit / component tests (vitest, co-located `*.test.tsx` per CLAUDE.md): navigation
  entry and action control are hidden without the permission and shown with it; the gate reads the set
  rather than a role name.

## Phase 3: graceful denial

- [ ] **3.1** Replace raw transport-error rendering on a `403` with a human-readable no-access state
  for the affected surface or control.
- [ ] **3.2** On an unanticipated `403`, refetch the session permission set so the stale affordance is
  hidden on subsequent renders (self-heal the snapshot-staleness window). Deduplicate and throttle the
  refetch so concurrent or repeated denials collapse to a single in-flight request rather than a refetch
  storm against the session endpoint.
- [ ] **3.3** Tests: deep-linking to a gated route without permission shows the no-access state, not a
  raw `API error: 403`; a `403` after a mid-session role revocation triggers a refetch and hides the
  affordance.

## Phase 4: documentation + validation gates

- [ ] **4.1** Update `docs/authz.md`: the UI reflects the same action vocabulary as the chokepoint, the
  permission set is advisory (server authoritative), and gating is not a security control.
- [ ] **4.2** Document the session-lifetime snapshot semantics (role changes apply on next login or on
  refetch) in `docs/authz.md` and the operator runbook.
- [ ] **4.3** Coverage on new code remains ≥ 80% on the SonarCloud gate; every new `ui/src/**` file
  carries a `*.test.{ts,tsx}` sibling (CLAUDE.md).
- [ ] **4.4** Spec-to-test traceability: at least one test references each new or modified SHALL/MUST
  scenario id (`tools/spectrace`).
