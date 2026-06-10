# Threat model and security refresh

**Cadence:** quarterly **Time budget:** 90-120 min **Trigger mode:** manual; also fires on demand whenever the data plane changes shape (new XPC seam, new HTTP endpoint, new third-party deployment channel, new persistence location)

## Why this matters

`docs/threat-model.md` is the architectural assertion of who can do what to whom. If it was written before mTLS, before the network extension, before per-context boundaries, before `/etc/fleet-edr.conf`, before the QA VM existed - then it isn't a threat model, it's a fossil. New threats become invisible because they're not on the map.

CodeQL, OSV-scanner, and Scorecard catch implementation-level CVEs and known patterns. They do NOT catch:

- New trust boundaries that nobody documented (e.g. a new XPC sender)
- Trust boundaries removed but still asserted in the doc
- Threats that the previous model deliberately scoped out and that have since become in-scope (e.g. per-team isolation inside a single deployment if the customer's org structure changes)
- Authn / authz design assumptions that no longer hold (sessions vs API tokens, CSRF on `POST /api/...`, etc.)

## Scope

Primary: `docs/threat-model.md`. Supporting: `docs/architecture.md`, `docs/api.md`, `SECURITY.md`, anything under `docs/install-*.md` describing trust boundaries during install.

## Steps

### 1. Boundaries inventory

List every trust boundary the system actually has, today, by inspection of the code:

| Boundary | Source of truth |
| --- | --- |
| Agent ↔ extension (XPC) | `extension/edr/` Mach service registration + `agent/` XPC client |
| Agent ↔ server (HTTP/mTLS) | `agent/uploader` + `server/endpoint/internal/enroll` + `server/endpoint/internal/middleware` |
| Server ↔ MySQL | `server/*/internal/mysql` |
| Server ↔ UI (browser session) | `server/identity/middleware` + `ui/src/` |
| Server ↔ operator REST surface | per-context `server/<bounded-context>/internal/operator/` (`detection`, `rules`, `endpoint`, `response`) plus `server/identity/internal/{login,oidc,breakglass,middleware}` for the auth boundary |
| Install / enroll secret distribution | `packaging/` + `/etc/fleet-edr.conf` |
| Fleet → EDR install | Fleet install script + signed `.pkg` + `.mobileconfig` |

For each boundary:

- Authentication mechanism in use today
- Authorization model
- Confidentiality (TLS, file perms)
- Integrity (signatures, hashes, mTLS, audit token verification)
- What the threat model currently says about it

If reality and the doc disagree, the doc loses.

### 2. New surfaces

Diff the current boundary list against the threat model's enumerated boundaries. New surfaces (added since the last refresh) must be added - even if "secure by construction", document the assumption.

### 3. Threat-actor list

The model should name the actor classes it considers (unprivileged local user, privileged local user, attacker on the local network, attacker who has compromised the agent, etc.). For each, ask:

- Is the actor still in scope?
- Have the deploy assumptions changed in a way that adds an actor (e.g. multi-tenancy via Fleet)?
- Are there new mitigations that change what the actor can do?

### 4. Cross-check with ADRs

ADR-0003 (standalone product, not Fleet-integrated) is a load-bearing threat-model input - it scopes Fleet to "deployment channel only". Confirm the threat model still expresses that contract correctly.

### 5. Cross-check with `docs/best-practices.md` security items

Section "10. Security" (or wherever security items live in the best-practices doc) lists adopted vs unchecked items. Inconsistencies between the two docs are a red flag.

## Output

A PR titled `Threat model refresh YYYY-Q\d`. Body must include:

- The current boundary inventory (markdown table)
- A diff vs the previous version of the doc
- Any new threats added with rationale
- Any threats demoted to out-of-scope with rationale

## Prompt template

```text
Run the threat model and security refresh defined in
docs/maintenance/tasks/threat-model-and-security-refresh.md.

Step 1 - produce the boundaries inventory by inspecting the code, not by re-reading the threat model.
For each boundary in the task-file table, document the actual authn / authz / confidentiality /
integrity in use today.

Step 2 - diff against docs/threat-model.md. Flag every disagreement: doc says X, code does Y.

Step 3 - produce the threat-actor list. Confirm each actor class is still in scope and properly
mitigated.

Step 4 - cross-check ADR-0003 (Fleet positioning), ADR-0004 (bounded contexts) for any threat-model
implications.

Step 5 - cross-check docs/best-practices.md security section.

Update docs/threat-model.md. PR body must include the boundary inventory and a clear "what changed
and why" summary. Do NOT silently shrink the threat model - every demoted threat needs an explicit
rationale.

Time budget 2 hours. If the model needs a major rewrite, file an issue and stop after the boundary
inventory.
```

## Definition of done

- [ ] Boundaries inventory captured from current code.
- [ ] Every disagreement between code and doc resolved (doc updated).
- [ ] New trust boundaries since last refresh are now documented.
- [ ] Demoted threats have explicit rationale.
- [ ] PR cross-references ADR-0003 / ADR-0004 if their contract has shifted.
- [ ] Dated entry in `docs/maintenance/log.md`.
