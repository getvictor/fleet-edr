import { Fragment, useEffect, useMemo, useState } from "react";
import { fetchAttackNavigatorLayer, type AttackNavigatorLayer } from "../api";
import { Table, EmptyState } from "./ui/Table";
import { PageHeader } from "./ui/PageHeader";
import { Button } from "./ui/Button";
import { TECHNIQUE_CATALOG, type TechniqueMeta } from "./attack-techniques";
import "./AttackCoverage.scss";

// AttackCoverage renders the MITRE ATT&CK technique coverage that the
// registered detection rules provide. The data comes from the same
// /api/v1/admin/attack-coverage endpoint that procurement teams ingest as a
// Navigator layer JSON — but we render it in-app as a tactic-grouped table
// because a JSON download is unsatisfying as a demo prop. The pattern matches
// what Crowdstrike Falcon, SentinelOne Singularity, and Elastic Security all
// expose: tactic columns, technique rows, "covered by" linkable rule list.
//
// We still ship the JSON via the "Download Navigator layer" button so an
// operator can drop it into the upstream MITRE Navigator UI for the full
// matrix view if they want — that's the right tool for "look at all 14 tactics
// at once" and there's no point in re-implementing the matrix renderer here.

type TechniqueWithCoverage = TechniqueMeta & {
  coveringRules: string[];
  color: string;
};

interface CoverageGroup {
  tactic: string;
  techniques: TechniqueWithCoverage[];
}

// All 14 enterprise tactics in MITRE's canonical kill-chain order. Anything
// the catalog or server emits that isn't on this list lands at the end via
// the "leftover" pass below — never silently dropped.
const TACTIC_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export function AttackCoverage() {
  const [layer, setLayer] = useState<AttackNavigatorLayer | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetchAttackNavigatorLayer()
      .then((l) => { if (!cancelled) setLayer(l); })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load coverage");
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const downloadLayer = () => {
    if (!layer) return;
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement("a");
      a.href = url;
      a.download = "fleet-edr-attack-coverage.json";
      document.body.appendChild(a);
      try { a.click(); } finally { a.remove(); }
    } finally {
      URL.revokeObjectURL(url);
    }
  };

  const { groups, distinctRules } = useMemo(
    () => buildCoverageGroups(layer),
    [layer],
  );
  const totalCovered = layer?.techniques.length ?? 0;

  return (
    <>
      <PageHeader
        title="ATT&CK coverage"
        subtitle="MITRE ATT&CK techniques the deployed detection rules cover today."
        actions={
          <Button
            size="small"
            variant="inverse"
            onClick={downloadLayer}
            disabled={!layer}
            title="Export the same data as a MITRE ATT&CK Navigator layer JSON. Useful for procurement / threat-modeling teams who use the upstream Navigator UI; sec ops can read everything they need on this page."
          >
            Export JSON
          </Button>
        }
      />

      {error && <div className="form-error" role="alert">Error: {error}</div>}
      {loading && <EmptyState>Loading coverage...</EmptyState>}

      {!loading && layer && (
        <>
          <div className="attack-coverage__summary">
            <div className="attack-coverage__metric">
              <span className="attack-coverage__metric-num">{totalCovered}</span>
              <span className="attack-coverage__metric-label">techniques covered</span>
            </div>
            <div className="attack-coverage__metric">
              <span className="attack-coverage__metric-num">{distinctRules.size}</span>
              <span className="attack-coverage__metric-label">detection rules</span>
            </div>
            <div className="attack-coverage__metric">
              <span className="attack-coverage__metric-num">{groups.length}</span>
              <span className="attack-coverage__metric-label">tactics with coverage</span>
            </div>
          </div>

          {groups.length === 0
            ? <EmptyState>No coverage data yet.</EmptyState>
            : (
              // Single table for the whole page so column widths line up
              // across tactics (a per-tactic <Table> sized columns from
              // its own widest cell, producing a different layout per
              // section). Tactic names land in colspan rows that act as
              // visual section headers — same pattern Crowdstrike Falcon
              // and Elastic Security use for their ATT&CK coverage tables.
              <Table className="attack-coverage__table">
                <colgroup>
                  <col className="attack-coverage__col-id" />
                  <col className="attack-coverage__col-name" />
                  <col className="attack-coverage__col-rules" />
                </colgroup>
                <thead>
                  <tr>
                    <th>Technique</th>
                    <th>Name</th>
                    <th>Covered by</th>
                  </tr>
                </thead>
                <tbody>
                  {groups.map((g) => (
                    <Fragment key={g.tactic}>
                      <tr className="attack-coverage__tactic-row">
                        <th colSpan={3} scope="colgroup">{g.tactic}</th>
                      </tr>
                      {g.techniques.map((t) => (
                        <tr key={t.id}>
                          <td>
                            <a
                              className="attack-coverage__technique-id"
                              href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              {t.id}
                            </a>
                          </td>
                          <td>{t.name}</td>
                          <td>
                            {t.coveringRules.map((r, i) => (
                              <span key={r}>
                                {i > 0 && ", "}
                                <code>{r}</code>
                              </span>
                            ))}
                          </td>
                        </tr>
                      ))}
                    </Fragment>
                  ))}
                </tbody>
              </Table>
            )}
        </>
      )}
    </>
  );
}

// parseCoveringRules pulls rule IDs out of the Navigator-layer "Covered by:"
// comment string. The server formats it as "Covered by: rule_a, rule_b". We
// keep this lenient: anything after the first colon, split on "," and trim
// whitespace from each piece — so a missing space after the comma still
// parses cleanly.
function parseCoveringRules(comment: string | undefined): string[] {
  if (!comment) return [];
  const colon = comment.indexOf(":");
  const tail = colon === -1 ? comment : comment.slice(colon + 1);
  return tail.split(",").map((s) => s.trim()).filter(Boolean);
}

// buildCoverageGroups runs once per layer fetch (memoised by the caller) and
// returns the rendered shape: tactics in MITRE order followed by anything
// else (Unmapped, novel tactics) at the end. It also collects the distinct
// covering-rule set in the same pass so we don't walk the techniques twice.
function buildCoverageGroups(
  layer: AttackNavigatorLayer | null,
): { groups: CoverageGroup[]; distinctRules: Set<string> } {
  const distinctRules = new Set<string>();
  const groups: CoverageGroup[] = [];
  if (!layer) return { groups, distinctRules };

  const byTactic = new Map<string, TechniqueWithCoverage[]>();
  for (const t of layer.techniques) {
    const meta = TECHNIQUE_CATALOG[t.techniqueID] ?? {
      id: t.techniqueID,
      name: t.techniqueID,
      tactic: "Unmapped",
    };
    const rules = parseCoveringRules(t.comment);
    for (const r of rules) distinctRules.add(r);
    const list = byTactic.get(meta.tactic) ?? [];
    list.push({ ...meta, coveringRules: rules, color: t.color ?? "" });
    byTactic.set(meta.tactic, list);
  }

  const seen = new Set<string>();
  const push = (tactic: string) => {
    const list = byTactic.get(tactic);
    if (!list) return;
    list.sort((a, b) => a.id.localeCompare(b.id));
    groups.push({ tactic, techniques: list });
    seen.add(tactic);
  };
  for (const tactic of TACTIC_ORDER) push(tactic);
  // Render anything that didn't match TACTIC_ORDER at the end (Unmapped,
  // future ATT&CK additions, casing/spelling drift) so coverage rows can
  // never silently disappear.
  for (const tactic of byTactic.keys()) {
    if (!seen.has(tactic)) push(tactic);
  }
  return { groups, distinctRules };
}
