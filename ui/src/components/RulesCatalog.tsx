import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { fetchRuleDocs, type RuleDocEntry } from "../api";
import { Badge } from "./ui/Badge";
import { severityBadgeVariant } from "./ui/severity";
import { EmptyState, Table } from "./ui/Table";
import { Input, Select } from "./ui/Input";
import { PageHeader } from "./ui/PageHeader";
import { ruleModeLabel } from "./ruleMode";
import "./RulesCatalog.scss";

// The origin the server reports for a rule written on this deployment (server/rules/api: LocalOrigin). The server records provenance
// when a document is stored rather than inferring it from a path, and this value is how the rules API reports that record, so it is
// what separates an operator's own rules from shipped ones.
const localOrigin = "Locally authored";

type OwnershipFilter = "all" | "shipped" | "yours";

// modeLabel names the mode a rule runs in. A server that does not report it (an older replica mid-upgrade) gets "Unknown" rather than
// the rule's declared default: the declaration is not the mode in force, and a rule an operator disabled would read as running.
function modeLabel(rule: RuleDocEntry): string {
  if (rule.mode === undefined) return "Unknown";
  const label = ruleModeLabel(rule.mode);
  return rule.mode_source === "setting" ? `${label} (set)` : label;
}

type Ownership = "shipped" | "yours" | "unknown";

// ownership says whether a rule shipped or was written on this deployment. An absent origin comes only from a server that predates
// reporting one, and it is "unknown", not "shipped": counting it as shipped would hide an operator's own rule from the Yours filter.
function ownership(rule: RuleDocEntry): Ownership {
  if (rule.origin === undefined) return "unknown";
  return rule.origin === localOrigin ? "yours" : "shipped";
}

// RulesCatalog is the browsable list of every rule this deployment runs (issue #1001). Before it, the rule detail page was reachable
// only by deep link from an alert or the coverage page, so an operator could not see what the deployment detects.
//
// Read-only on purpose. Writing rules lands separately, and a catalogue an operator can read is useful on its own.
export function RulesCatalog() {
  const [rules, setRules] = useState<RuleDocEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [ownershipFilter, setOwnershipFilter] = useState<OwnershipFilter>("all");

  useEffect(() => {
    let cancelled = false;
    fetchRuleDocs()
      .then((result) => {
        if (!cancelled) setRules(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Unknown error");
      });
    return () => { cancelled = true; };
  }, []);

  const visible = useMemo(() => {
    if (rules === null) return [];
    const needle = query.trim().toLowerCase();
    return rules
      .filter((r) => ownershipFilter === "all" || ownership(r) === ownershipFilter)
      .filter((r) => needle === "" || r.id.toLowerCase().includes(needle) || r.doc.title.toLowerCase().includes(needle))
      .sort((a, b) => a.doc.title.localeCompare(b.doc.title));
  }, [rules, query, ownershipFilter]);

  const ownCount = rules?.filter((r) => ownership(r) === "yours").length ?? 0;

  const filters = (
    <div className="rules-catalog__filters">
      <Input
        id="rules-catalog-search"
        label="Search:"
        value={query}
        placeholder="Name or identifier"
        onChange={(e) => { setQuery(e.target.value); }}
      />
      <Select
        id="rules-catalog-ownership"
        label="Show:"
        value={ownershipFilter}
        onChange={(e) => { setOwnershipFilter(e.target.value as OwnershipFilter); }}
      >
        <option value="all">All rules</option>
        <option value="shipped">Shipped</option>
        <option value="yours">Yours</option>
      </Select>
    </div>
  );

  return (
    <>
      <PageHeader title="Rules" actions={filters} />
      {error !== null && <EmptyState>Rules could not be loaded: {error}</EmptyState>}
      {error === null && rules === null && <EmptyState>Loading rules...</EmptyState>}
      {rules !== null && (
        <p className="rules-catalog__summary">
          {`${String(rules.length)} rule${rules.length === 1 ? "" : "s"}, ${String(ownCount)} written on this deployment.`}
        </p>
      )}
      {rules !== null && visible.length === 0 && <EmptyState>No rules match.</EmptyState>}
      {visible.length > 0 && (
        <Table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Severity</th>
              <th>Mode</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((r) => (
              <tr key={r.id}>
                <td>
                  <Link className="link-button" to={`/rules/${encodeURIComponent(r.id)}`}>
                    {r.doc.title}
                  </Link>
                  <div>
                    <code className="rules-catalog__id">{r.id}</code>
                  </div>
                </td>
                <td>
                  <Badge variant={severityBadgeVariant(r.doc.severity)}>{r.doc.severity || "unspecified"}</Badge>
                </td>
                <td>{modeLabel(r)}</td>
                <td>
                  {ownership(r) === "yours" && <Badge variant="info">Yours</Badge>}
                  {ownership(r) === "unknown" && <span className="rules-catalog__shipped">Unknown</span>}
                  {ownership(r) === "shipped" && (
                    <>
                      <span className="rules-catalog__shipped">Shipped</span>
                      {/* The imported corpus's licence requires its authors be credited wherever the rule is described. */}
                      <div className="rules-catalog__origin">{r.origin}</div>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </>
  );
}
