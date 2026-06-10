# Best-practices refresh

**Cadence:** quarterly **Time budget:** 90 min **Trigger mode:** manual

## Why this matters

[`docs/best-practices.md`](../../best-practices.md) is explicitly a "living self-audit" against industry peers (CrowdStrike, SentinelOne, Elastic Security, Falco, Kubernetes, Sigstore, osquery, Fleet, Wazuh). Items get checked when the repo adopts them and unchecked when they're known gaps. The document only serves its purpose if the _unchecked_ items are revisited as the industry moves: a gap that was acceptable a year ago (e.g. SBOMs, Sigstore signing, OCSF export) may now be a credibility liability for an open-source EDR.

This task does the opposite of the doc-accuracy sweep: that one fixes broken references; this one updates the _substance_ of the audit against what peers shipped this quarter.

## Scope

Primary: [`docs/best-practices.md`](../../best-practices.md). Secondary: [`docs/threat-model.md`](../../threat-model.md) (covered by its own task) and [`docs/architecture.md`](../../architecture.md) (drift caught by the doc-accuracy sweep).

## Steps

### 1. Re-confirm checked items

For every `[x]` in the document, verify the cited file / function / dashboard still exists and still implements the claim. Demote to `[~]` if partial, `[ ]` if regressed. This is the only place this task overlaps with doc-accuracy: fold the result into either PR, but always re-verify the claim, not just the path.

### 2. Industry delta scan

Skim the latest releases and roadmap notes from these projects (read their CHANGELOG / release notes / blog within the last quarter):

- **Falco**: new ESF / eBPF detection patterns, rule-format changes
- **Sigstore** (cosign / fulcio / rekor): signing, attestation, transparency log practices
- **OpenSSF Scorecard**: newly added checks (already wired into `scorecard.yml`)
- **OCSF**: schema changes; relevance of new event classes
- **MITRE ATT&CK**: new techniques in the latest version (vs whatever the rules currently map to)
- **OWASP**: Top 10 (web), API Top 10, LLM Top 10 if applicable
- **NIST CSF / 800-171 / 800-53**: only if a customer asks; otherwise skip
- **Atomic Red Team / Stratus Red Team / Caldera**: new scenarios worth replaying
- **CrowdStrike / SentinelOne / Elastic Security** public release notes: capabilities they shipped that move the bar
- **Fleet, Jamf Pro, Jamf Protect** release notes (we care about deployment surface)

Note: this is _industry awareness_, not a duty to adopt everything. The output is a delta list, not a backlog explosion.

### 3. Update the doc

For each delta:

- If the repo already does it informally, add a checked or partial item with a code reference.
- If it's a real gap and worth doing, leave it unchecked with a one-line rationale (which keeps it visible).
- If it's a real gap that's deliberately _not_ worth doing, mark it `[-]` with the rationale ("we don't do FIM because the per-host I/O cost outweighs the detection lift for our threat model").
- If a checked item has been _deprecated_ by the industry, demote it and explain.

### 4. Cross-link

Where the doc cites a new ADR-worthy decision (e.g. "decided not to ship a Prometheus endpoint, OTel only"), check whether an ADR exists. If not, add a candidate to the ADR audit gap list.

## Output

A PR titled `Best-practices refresh YYYY-Q\d`. PR body summarises:

- Items demoted (with rationale)
- Items newly checked
- Industry deltas considered and rejected (with rationale)
- New ADR candidates surfaced

## Prompt template

```text
Run the best-practices refresh defined in docs/maintenance/tasks/best-practices-refresh.md.

Step 1 - re-verify every [x] item in docs/best-practices.md against the current code. Demote any
that have regressed.

Step 2 - research the latest releases (last 90 days) from: Falco, Sigstore, OpenSSF Scorecard, OCSF,
MITRE ATT&CK, OWASP, Atomic Red Team / Stratus Red Team / Caldera, CrowdStrike, SentinelOne, Elastic
Security, Fleet. Use WebSearch / WebFetch. For each release, ask: does it move the bar on any
unchecked item, or introduce a new bar we don't have? Compile a delta list.

Step 3 - update docs/best-practices.md. Mark items [x] / [~] / [ ] / [-] with one-line rationale.
Don't delete unchecked items.

Step 4 - for any items that imply a load-bearing decision ("OTel-only metrics", "no FIM"), check
docs/adr/. If no ADR captures it, add to the ADR audit gap list (file an issue).

Open one PR. Time budget: 90 minutes. If a single delta turns into a multi-day implementation
discussion, file it as an issue and continue.
```

## Definition of done

- [ ] Every checked item re-verified.
- [ ] Industry-delta scan covered the listed sources from the last 90 days.
- [ ] PR body summarises deltas, with explicit rationale for each rejected item.
- [ ] ADR-worthy decisions surfaced as issues.
- [ ] Dated entry in [`docs/maintenance/log.md`](../log.md) with the delta count.
