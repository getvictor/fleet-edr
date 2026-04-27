import { useEffect, useState } from "react";
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

const TACTIC_ORDER = [
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

  const groups: CoverageGroup[] = [];
  if (layer) {
    // Index by technique id, attach catalog metadata, group by tactic.
    const byTactic = new Map<string, TechniqueWithCoverage[]>();
    for (const t of layer.techniques) {
      const meta = TECHNIQUE_CATALOG[t.techniqueID] ?? {
        id: t.techniqueID,
        name: t.techniqueID,
        tactic: "Unmapped",
      };
      const rules = parseCoveringRules(t.comment);
      const row: TechniqueWithCoverage = { ...meta, coveringRules: rules, color: t.color ?? "" };
      const list = byTactic.get(meta.tactic) ?? [];
      list.push(row);
      byTactic.set(meta.tactic, list);
    }
    for (const tactic of TACTIC_ORDER) {
      const list = byTactic.get(tactic);
      if (list) {
        list.sort((a, b) => a.id.localeCompare(b.id));
        groups.push({ tactic, techniques: list });
      }
    }
    const unmapped = byTactic.get("Unmapped");
    if (unmapped) {
      unmapped.sort((a, b) => a.id.localeCompare(b.id));
      groups.push({ tactic: "Unmapped", techniques: unmapped });
    }
  }

  const totalCovered = layer?.techniques.length ?? 0;
  const distinctRules = new Set<string>();
  if (layer) {
    for (const t of layer.techniques) {
      for (const r of parseCoveringRules(t.comment)) distinctRules.add(r);
    }
  }

  return (
    <>
      <PageHeader
        title="ATT&CK coverage"
        subtitle="MITRE ATT&CK techniques the deployed detection rules cover today."
        actions={
          <div className="attack-coverage__actions">
            <Button size="small" variant="inverse" onClick={downloadLayer} disabled={!layer}>
              Download Navigator layer
            </Button>
            <a
              className="attack-coverage__navigator-link"
              href="https://mitre-attack.github.io/attack-navigator/"
              target="_blank"
              rel="noopener noreferrer"
            >
              Open MITRE Navigator &rarr;
            </a>
          </div>
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
            : groups.map((g) => (
              <section key={g.tactic} className="attack-coverage__tactic">
                <h2 className="attack-coverage__tactic-name">{g.tactic}</h2>
                <Table>
                  <thead>
                    <tr>
                      <th style={{ width: "11ch" }}>Technique</th>
                      <th>Name</th>
                      <th>Covered by</th>
                    </tr>
                  </thead>
                  <tbody>
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
                  </tbody>
                </Table>
              </section>
            ))}
        </>
      )}
    </>
  );
}

// parseCoveringRules pulls rule IDs out of the Navigator-layer "Covered by:"
// comment string. The server formats it as "Covered by: rule_a, rule_b". We
// keep this lenient: anything after the first colon, split on ", ".
function parseCoveringRules(comment: string | undefined): string[] {
  if (!comment) return [];
  const colon = comment.indexOf(":");
  const tail = colon === -1 ? comment : comment.slice(colon + 1);
  return tail.split(",").map((s) => s.trim()).filter(Boolean);
}
