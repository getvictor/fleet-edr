import { useEffect, useMemo, useState } from "react";
import { Link, useLocation } from "react-router";
import { fetchRuleDocs, type RuleDocEntry } from "../api";
import { Badge } from "./ui/Badge";
import { severityBadgeVariant } from "./ui/severity";
import { EmptyState, Table } from "./ui/Table";
import { Input, Select } from "./ui/Input";
import { PageHeader } from "./ui/PageHeader";
import { PermissionAction, useCan } from "../permissions-core";
import { RulePackPanel } from "./RulePackPanel";
import { ruleModeLabel } from "./ruleMode";
import { isLocallyAuthored } from "./ruleOrigin";
import "./RulesCatalog.scss";


type OwnershipFilter = "all" | "built-in" | "yours";

// modeLabel names the mode a rule runs in. A server that does not report it (an older replica mid-upgrade) gets "Unknown" rather than
// the rule's declared default: the declaration is not the mode in force, and a rule an operator disabled would read as running.
function modeLabel(rule: RuleDocEntry): string {
  if (rule.mode === undefined) return "Unknown";
  const label = ruleModeLabel(rule.mode);
  return rule.mode_source === "setting" ? `${label} (set)` : label;
}

type Ownership = "built-in" | "yours" | "unknown";

// ownership says whether a rule came with the product or was written on this deployment. An absent origin comes only from a server
// that predates reporting one, and it is "unknown", not "built-in": counting it as built-in would hide an operator's own rule from
// the Yours filter.
function ownership(rule: RuleDocEntry): Ownership {
  if (rule.origin === undefined) return "unknown";
  return isLocallyAuthored(rule.origin) ? "yours" : "built-in";
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
  const can = useCan();
  const canWrite = can(PermissionAction.RuleContentWrite);
  // Set by a rule page after a delete, so the operator lands somewhere that confirms it.
  const deleted = (useLocation().state as { deleted?: string } | null)?.deleted;

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
    <div className="rules-catalog__filters" role="search" aria-label="Filter rules">
      {/* No visible labels. Input stacks its label above the box in uppercase, Select puts its own beside the control in mixed
          case, so the two sat in different places in the same row and read as unrelated. Each control says what it does on its
          own instead: the placeholder for the box, and option text that is a whole phrase for the dropdown, so the collapsed
          control still reads as a statement about what is listed. Accessible names are kept on both. This is the filter bar the
          application-control page already uses. */}
      <Input
        id="rules-catalog-search"
        type="search"
        value={query}
        placeholder="Search name or identifier"
        aria-label="Search rules by name or identifier"
        onChange={(e) => { setQuery(e.target.value); }}
      />
      <Select
        id="rules-catalog-ownership"
        aria-label="Filter rules by who wrote them"
        value={ownershipFilter}
        onChange={(e) => { setOwnershipFilter(e.target.value as OwnershipFilter); }}
      >
        <option value="all">All rules</option>
        <option value="built-in">Built-in rules</option>
        <option value="yours">Your rules</option>
      </Select>
      {canWrite && (
        <Link className="button button--primary" to="/rules/new">
          New rule
        </Link>
      )}
    </div>
  );

  return (
    <>
      <PageHeader title="Rules" actions={filters} />
      {deleted !== undefined && (
        <p className="rules-catalog__summary" role="status">
          Deleted <code>{deleted}</code>. The server stops evaluating it when it next reloads its rules, within 30 seconds, and it may be
          listed here until then.
        </p>
      )}
      <RulePackPanel canWrite={canWrite} />
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
                  {ownership(r) === "unknown" && <span className="rules-catalog__built-in">Unknown</span>}
                  {ownership(r) === "built-in" && (
                    <>
                      <span className="rules-catalog__built-in">Built-in</span>
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
