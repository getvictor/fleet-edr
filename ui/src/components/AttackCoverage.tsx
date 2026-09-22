import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { useCan, PermissionAction } from "../permissions-core";
import { fetchAttackNavigatorLayer, type AttackNavigatorLayer } from "../api";
import { Table, EmptyState } from "./ui/Table";
import { PageHeader } from "./ui/PageHeader";
import { SubNav } from "./ui/SubNav";
import { RULES_TABS, RULES_TABS_LABEL } from "./rulesTabs";
import { Button } from "./ui/Button";
import { StatCard, SummaryStrip } from "./ui/StatCard";
import { TECHNIQUE_CATALOG, TACTIC_ORDER, type TechniqueMeta } from "./attack-techniques.generated";
import "./AttackCoverage.scss";

// AttackCoverage renders the MITRE ATT&CK technique coverage that the
// registered detection rules provide. The data comes from the same
// /api/attack-coverage endpoint that procurement teams ingest as a
// Navigator layer JSON, but we render it in-app as a tactic-grouped table
// because a JSON download is unsatisfying as a demo prop. The pattern matches
// what Crowdstrike Falcon, SentinelOne Singularity, and Elastic Security all
// expose: tactic columns, technique rows, "covered by" linkable rule list.
//
// We still ship the JSON via the "Export JSON" button so an operator can
// drop it into the upstream MITRE Navigator UI for the full matrix view if
// they want. That's the right tool for "look at all 14 tactics at once" and
// there's no point in re-implementing the matrix renderer here.

type TechniqueWithCoverage = TechniqueMeta & {
  coveringRules: string[];
  color: string;
};

interface CoverageGroup {
  tactic: string;
  techniques: TechniqueWithCoverage[];
}

// A gap is a technique this sensor could in principle cover and no rule does.
interface GapGroup {
  tactic: string;
  techniques: TechniqueMeta[];
}

// COVERED_SCOPE is what a reader is choosing between: the techniques rules cover, the ones they do not, or both.
type CoverageScope = "covered" | "gaps";

// SENSOR_PLATFORM is the platform this product watches. A technique ATT&CK does not list for it is not a gap in this deployment's
// coverage, it is a technique that cannot be run against the estate: of the 697 live enterprise techniques only around half carry
// macOS, and counting the rest as missing would bury the real gaps under Windows registry and cloud entries.
const SENSOR_PLATFORM = "macOS";

// inSensorScope reports whether ATT&CK lists this technique for the platform the product watches. A technique with no platforms
// recorded is treated as in scope: the table is generated from MITRE's bundle, and a missing list is a fact about the bundle
// rather than evidence the technique is irrelevant, so it is shown rather than silently dropped.
function inSensorScope(meta: TechniqueMeta): boolean {
  return meta.platforms.length === 0 || meta.platforms.includes(SENSOR_PLATFORM);
}

// buildGapGroups returns the in-scope techniques no rule covers, grouped by tactic in the same order the covered table uses, so
// the two views of the matrix read alike.
function buildGapGroups(layer: AttackNavigatorLayer | null): GapGroup[] {
  if (!layer) return [];
  const covered = new Set(layer.techniques.map((t) => t.techniqueID));
  const byTactic = new Map<string, TechniqueMeta[]>();
  for (const meta of Object.values(TECHNIQUE_CATALOG)) {
    if (covered.has(meta.id) || !inSensorScope(meta)) continue;
    const list = byTactic.get(meta.tactic) ?? [];
    list.push(meta);
    byTactic.set(meta.tactic, list);
  }
  const groups: GapGroup[] = [];
  for (const tactic of TACTIC_ORDER) {
    const techniques = byTactic.get(tactic);
    if (techniques) groups.push({ tactic, techniques: [...techniques].sort((a, b) => a.id.localeCompare(b.id)) });
  }
  // Anything under a tactic the order does not name still has to appear, for the same reason the covered table keeps its leftovers.
  for (const [tactic, techniques] of byTactic) {
    if (!TACTIC_ORDER.includes(tactic)) groups.push({ tactic, techniques });
  }
  return groups;
}

// newRuleHref opens the authoring surface with the technique already named, so a gap is answered by writing the rule for it rather
// than by remembering which one the reader was looking at. Sigma's tag vocabulary is lowercase and `attack.` prefixed.
function newRuleHref(id: string): string {
  return `/rules/new?technique=${encodeURIComponent(id)}`;
}

// All 14 enterprise tactics in MITRE's canonical kill-chain order. Anything
// the catalog or server emits that isn't on this list lands at the end via
// the "leftover" pass below, never silently dropped.
export function AttackCoverage() {
  // The Coverage page is deliberately open to every operator, but Detection tuning is not. Offering the link to someone
  // who would land on the no-access page is worse than not offering it: the card still carries the number, which is the
  // part they can act on by asking someone who has the permission.
  const canTune = useCan()(PermissionAction.DetectionConfigRead);
  const [layer, setLayer] = useState<AttackNavigatorLayer | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetchAttackNavigatorLayer()
      .then((l) => {
        if (!cancelled) setLayer(l);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load coverage");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
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
      try {
        a.click();
      } finally {
        a.remove();
      }
    } finally {
      URL.revokeObjectURL(url);
    }
  };

  const { groups, distinctRules } = useMemo(() => buildCoverageGroups(layer), [layer]);
  // Which half of the matrix is being read. Covered is the default because it is what the deployment has; the gaps are what it
  // could do next, which is a question asked deliberately rather than on arrival.
  const [scope, setScope] = useState<CoverageScope>("covered");
  const gapGroups = useMemo(() => buildGapGroups(layer), [layer]);
  // The denominator this page could never state before: how many techniques the sensor's platform even has. Without it the
  // covered count is a number with nothing to be a fraction of, and a reader cannot tell sixty-four out of ninety from
  // sixty-four out of three hundred and fifty-six.
  const inScopeTotal = useMemo(() => Object.values(TECHNIQUE_CATALOG).filter(inSensorScope).length, []);
  const gapCount = useMemo(() => gapGroups.reduce((n, g) => n + g.techniques.length, 0), [gapGroups]);
  const canWriteRules = useCan()(PermissionAction.RuleContentWrite);
  // Split by whether anything covering the technique actually alerts. The server scores a technique below 1 when every rule
  // covering it raises nothing as built in (issue #764), and most of the catalog is now in that state, so a single "techniques
  // covered" figure would tell a reader the product raises alerts for sixty-odd techniques when it raises them for thirteen.
  //
  // The wording stays mode-neutral. A sub-1 score means monitor OR disabled, and calling it "monitored" would misstate a disabled
  // rule, which records nothing rather than recording without alerting. The score does not distinguish them and neither should
  // this label; what both cases share, and all this card can honestly claim, is that nothing there alerts.
  //
  // "by default" is the other half of that honesty. The score is derived from each rule's catalog default, not from the settings
  // this deployment has stored, so a promoted vendored rule still scores 0.5 and a disabled authored rule still scores 1. Without
  // the qualifier these cards would read as live state and be wrong for exactly the deployments that have tuned anything.
  const alerting = layer?.techniques.filter((t) => t.score >= 1).length ?? 0;
  const notAlerting = (layer?.techniques.length ?? 0) - alerting;

  return (
    <>
      <PageHeader
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
      <SubNav items={RULES_TABS} label={RULES_TABS_LABEL} />

      {error && (
        <div className="form-error" role="alert">
          Error: {error}
        </div>
      )}
      {loading && <EmptyState>Loading coverage...</EmptyState>}

      {!loading && layer && (
        <>
          <SummaryStrip>
            <StatCard
              accent="green"
              value={alerting}
              label="techniques alerting by default"
              hint="Techniques with at least one rule that alerts out of the box. Counted from each rule's catalog default, not from what this deployment has tuned."
            />
            {notAlerting > 0 && (
              <StatCard
                accent="neutral"
                value={notAlerting}
                // The number stays. It is the single most load-bearing fact on this page: most of the catalog ships silent,
                // and a reader who takes "alerting by default" as the coverage figure is off by a factor of five. What it
                // needed was somewhere to go. Left bare it reads as a defect to switch off, when these rules ship in monitor
                // mode deliberately, because promoting them without tuning buries the alerts that matter under theirs.
                //
                // The label is the short mirror of the card beside it, so the pair reads as one contrast rather than as a
                // caption and a paragraph. Two words of it are not negotiable, though. "techniques" stays because this card
                // sits beside a count of RULES and a count of TACTICS, and a bare "silent by default" reads as either.
                // "by default" stays because the score comes from each rule's catalog default rather than from this
                // deployment's settings. The detail moved to the hint, and the LINK stays visible: it is an action.
                hint="Techniques covered only by rules that do not alert out of the box. Most ship in monitor mode, recording matches without raising an alert; a few ship disabled and record nothing. Promoting all of them at once buries the alerts that matter. Counted from catalog defaults, not from what this deployment has tuned."
                label={(
                  <>
                    techniques silent by default{canTune && (
                      <>
                        {" "}
                        <Link className="attack-coverage__tune-link" to="/detection-config">promote or tune</Link>
                      </>
                    )}
                  </>
                )}
              />
            )}
            <StatCard accent="green" value={distinctRules.size} label="detection rules" />
            <StatCard accent="green" value={groups.length} label="tactics with coverage" />
            {/* The fraction the page could not state before. A covered count with no denominator cannot tell a reader sixty-four
                out of ninety from sixty-four out of three hundred and fifty-six, and the second is the honest picture. */}
            <StatCard
              accent="neutral"
              value={gapCount}
              label={`macOS techniques with no rule, of ${String(inScopeTotal)}`}
              hint="Techniques ATT&CK lists for macOS that no rule in this deployment covers. Techniques ATT&CK does not list for macOS are left out: they cannot be run against this estate, and counting them would bury the real gaps."
            />
          </SummaryStrip>

          {/* Which half of the matrix to read. A nav of links would put this in the URL, but the choice is a filter over one
              page's table rather than a surface of its own, so it stays a control. */}
          <fieldset className="attack-coverage__scope">
            {/* A fieldset with a legend rather than a div carrying role="group": the native element says the same thing without
                an ARIA role, which is what the enforcement choice on the application-control dialogs already does here. The
                legend is the group's name and is read rather than shown, since the two buttons say what they select. */}
            <legend className="attack-coverage__scope-legend">Which techniques to list</legend>
            <button
              type="button"
              className={`attack-coverage__scope-item${scope === "covered" ? " attack-coverage__scope-item--active" : ""}`}
              aria-pressed={scope === "covered"}
              onClick={() => { setScope("covered"); }}
            >
              Covered
            </button>
            <button
              type="button"
              className={`attack-coverage__scope-item${scope === "gaps" ? " attack-coverage__scope-item--active" : ""}`}
              aria-pressed={scope === "gaps"}
              onClick={() => { setScope("gaps"); }}
            >
              Not covered
            </button>
          </fieldset>

          {groups.length === 0 ? (
            <EmptyState>No coverage data yet.</EmptyState>
          ) : (
            // Single table for the whole page so column widths line up
            // across tactics (a per-tactic <Table> sized columns from
            // its own widest cell, producing a different layout per
            // section). Tactic names land in colspan rows that act as
            // visual section headers, the same pattern Crowdstrike Falcon
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
                  {/* The third column is what the row has to say about itself, which differs by which half is listed: the rules
                      covering a technique, or the rule that is missing. Left as "Covered by" over the gaps it labelled a column
                      of offers to write one as though they were coverage. */}
                  <th>{scope === "covered" ? "Covered by" : "No rule yet"}</th>
                </tr>
              </thead>
              {/* One <tbody> per tactic with scope="rowgroup" on the
                    header: that's the HTML5 idiom for grouping rows under a
                    label, which lets screen readers announce the tactic as
                    context for each technique row. Visually identical to a
                    Fragment-with-shared-tbody approach. */}
              {scope === "covered" && groups.map((g) => (
                <tbody key={g.tactic}>
                  <tr className="attack-coverage__tactic-row">
                    <th colSpan={3} scope="rowgroup">
                      {g.tactic}
                    </th>
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
                            <Link
                              className="attack-coverage__rule-link"
                              to={`/rules/${r}`}
                              title="Open this detection rule's documentation"
                            >
                              <code>{r}</code>
                            </Link>
                          </span>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              ))}
              {scope === "gaps" && gapGroups.map((g) => (
                <tbody key={g.tactic}>
                  <tr className="attack-coverage__tactic-row">
                    <th colSpan={3} scope="rowgroup">
                      {g.tactic}
                    </th>
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
                        {/* Offered only to an operator who may write one. Without the permission the row still carries the gap,
                            which is the part they can act on by asking someone who has it, the same way the tuning link above
                            is handled. */}
                        {canWriteRules && (
                          <Link
                            className="attack-coverage__rule-link"
                            to={newRuleHref(t.id)}
                            title={`Write a detection rule for ${t.id}`}
                          >
                            Write a rule
                          </Link>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              ))}
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
// whitespace from each piece, so a missing space after the comma still
// parses cleanly.
function parseCoveringRules(comment: string | undefined): string[] {
  if (!comment) return [];
  const colon = comment.indexOf(":");
  const tail = colon === -1 ? comment : comment.slice(colon + 1);
  return tail
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// buildCoverageGroups runs once per layer fetch (memoised by the caller) and
// returns the rendered shape: tactics in MITRE order followed by anything
// else (Unmapped, novel tactics) at the end. It also collects the distinct
// covering-rule set in the same pass so we don't walk the techniques twice.
function buildCoverageGroups(layer: AttackNavigatorLayer | null): { groups: CoverageGroup[]; distinctRules: Set<string> } {
  const distinctRules = new Set<string>();
  const groups: CoverageGroup[] = [];
  if (!layer) return { groups, distinctRules };

  const byTactic = new Map<string, TechniqueWithCoverage[]>();
  for (const t of layer.techniques) {
    const meta = TECHNIQUE_CATALOG[t.techniqueID] ?? {
      id: t.techniqueID,
      name: t.techniqueID,
      tactic: "Unmapped",
      tactics: ["Unmapped"],
    };
    const rules = parseCoveringRules(t.comment);
    for (const r of rules) distinctRules.add(r);
    // Under EVERY tactic ATT&CK gives it, not just the first. T1543.004 is both Persistence and Privilege Escalation, and
    // listing it under one made the other look uncovered when a rule covers it. The upstream matrix repeats a technique the
    // same way, so a reader comparing the two pages sees the same shape. The stat cards count layer.techniques and are
    // unaffected; "tactics with coverage" now counts the tactics actually covered rather than the ones that happened to be
    // listed first.
    const tactics = meta.tactics.length > 0 ? meta.tactics : [meta.tactic];
    for (const tactic of tactics) {
      const list = byTactic.get(tactic) ?? [];
      list.push({ ...meta, coveringRules: rules, color: t.color ?? "" });
      byTactic.set(tactic, list);
    }
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
