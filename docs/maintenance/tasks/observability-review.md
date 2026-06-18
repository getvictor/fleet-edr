# Observability review

**Cadence:** monthly **Time budget:** 45-60 min **Trigger mode:** manual; uses `mcp__signoz__*` per the global MEMORY rule

## Why this matters

OTel coverage drifts the same way docs drift. A new endpoint goes in without a span, a new code path raises errors that nobody sees because there's no metric for them, an alert keeps firing once a week with nobody investigating because it became background noise. The compounding cost is real: when an incident hits, the signal you needed is missing because nobody noticed the metric was never wired.

SigNoz is the source of truth for live behaviour (dashboards, alerts, traces, metrics). Browser screenshots are forbidden per MEMORY: every metric / trace claim must be verified through the SigNoz MCP tools.

Project policy: do NOT add a Prometheus `/metrics` endpoint. All metrics flow through OTel + the existing OTLP pipeline. This policy is currently captured in per-user MEMORY only; the `adr-audit` task gap list flags this as a candidate for a committed ADR so the policy outlives any single contributor's memory.

## Scope

- OTel instrumentation in `server/`, `agent/`, `internal/`
- SigNoz dashboards (production + load-test instances)
- SigNoz alert rules
- The OTel-only metrics policy stated above

## Steps

### 1. Coverage check

For each context's HTTP handlers, list registered routes (`grep -nE 'mux\.Handle|mux\.HandleFunc|r\.(Get|Post|Put|Delete)'`) and confirm:

- Every handler has request / latency / error metrics (or rolls up to a shared middleware that does).
- Every error path produces a span event or a structured log line that surfaces the error class.
- New routes added since last review are present in the dashboards.

### 2. Dashboard usefulness

Use `mcp__signoz__signoz_list_dashboards` to enumerate dashboards. For each:

- When was it last opened? (If SigNoz exposes view counts via its API; otherwise, ask in the team channel.)
- Does it answer a question someone is actually asking, or is it generic-status decoration?
- Are any panels broken (no data, wrong query, references a metric that no longer exists)?

Delete or fix dashboards that don't pass this bar. Theatre dashboards make real ones harder to find.

### 3. Alert noise audit

`mcp__signoz__signoz_list_alerts` and `mcp__signoz__signoz_get_alert_history` for each alert. For each:

- Fire rate over the last 30 days.
- Acknowledged vs auto-resolved.
- Was a real action ever taken from this alert? If not, either tune the threshold or delete.

Noisy alerts that nobody acts on are worse than missing alerts: they teach the team to ignore the channel.

### 4. New surface check

Cross-reference the boundaries inventory from [`threat-model-and-security-refresh`](threat-model-and-security-refresh.md). Each new boundary should have a metric (request count + latency + error rate). If it doesn't, file an issue.

### 5. Policy enforcement

Quick grep:

```bash
grep -rE 'prometheus\.|/metrics' server/ agent/ internal/ --include='*.go'
```

If anything new has snuck in, file it as a violation of the OTel-only policy and remove (or extract a justification ADR if the team genuinely wants to revisit the decision).

## Output

- A PR for any OTel instrumentation gaps fixed in code.
- Direct dashboard / alert changes in SigNoz, captured in the audit summary.
- Issues filed for everything else.

## Prompt template

```text
Run the observability review defined in docs/maintenance/tasks/observability-review.md.

Use mcp__signoz__* tools, not browser screenshots, per MEMORY guidance. Do NOT propose adding a
Prometheus /metrics endpoint - OTel only.

Step 1 - coverage check. List HTTP routes in server/ and confirm metric coverage. File issues for
gaps.

Step 2 - list SigNoz dashboards. For each, verify panels resolve to live data and that the
dashboard answers a real question. Note candidates for deletion.

Step 3 - list SigNoz alerts and their history. For each, compute fire rate; flag noisy alerts that
nobody acts on.

Step 4 - cross-check new trust boundaries from the threat-model task. Each should have request /
latency / error metrics.

Step 5 - grep for new prometheus / /metrics introductions; flag any.

Open one PR for code-level fixes; SigNoz changes go directly with a written-up summary in the PR
body. The docs/maintenance/log.md entry stays one tight line per the format at the top of that
file. Time budget 60 minutes.
```

## Definition of done

- [ ] HTTP route inventory matches OTel coverage; gaps filed.
- [ ] SigNoz dashboards reviewed; broken or theatre dashboards deleted or fixed.
- [ ] Alert noise audit done; noisy alerts tuned or removed.
- [ ] New trust boundaries have metric coverage.
- [ ] No new Prometheus instrumentation has snuck in.
- [ ] Dated entry in [`docs/maintenance/log.md`](../log.md).
