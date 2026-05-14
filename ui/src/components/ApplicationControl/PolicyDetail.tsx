import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getAppControlPolicy } from "../../api";
import type { ApplicationControlPolicy, ApplicationControlRule } from "../../types";
import { PageHeader } from "../ui/PageHeader";
import { Table, EmptyState } from "../ui/Table";
import { Button } from "../ui/Button";
import { Badge, type BadgeVariant } from "../ui/Badge";
import { AddRuleModal } from "./AddRuleModal";
import "./ApplicationControl.scss";

const SEVERITY_VARIANTS: Record<string, BadgeVariant> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

// truncateIdentifier renders the leading 16 chars of a SHA-256
// identifier so the rules table stays scannable without dropping the
// disambiguating prefix. Full value is in the row's title attribute
// for inspection. Identifiers shorter than the cap render verbatim
// — TEAMID / SIGNINGID rules (post-demo) would otherwise come back
// cropped.
const IDENTIFIER_DISPLAY_CHARS = 16;
function truncateIdentifier(value: string): string {
  if (value.length <= IDENTIFIER_DISPLAY_CHARS) return value;
  return value.slice(0, IDENTIFIER_DISPLAY_CHARS) + "…";
}

// PolicyDetail is the policy-rules surface the demo's Add Rule modal
// hangs off. Demo beat #2 (admin pastes a SHA-256, hits Save, sees
// the row appear) is its primary job; the per-row edit / disable /
// delete buttons render disabled with the "coming soon" tooltip
// pattern PoliciesList uses on its New Policy button. The Show
// History toggle is the audit-history scaffolding for post-demo
// work.
export function PolicyDetail() {
  const { id: idParam } = useParams<{ id: string }>();
  const policyID = idParam ? Number.parseInt(idParam, 10) : Number.NaN;
  const [policy, setPolicy] = useState<ApplicationControlPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);

  // refreshKey bumps to force a re-fetch (e.g. after Save in the
  // modal). useEffect below owns the actual fetch lifecycle so the
  // setState calls happen in async callbacks rather than synchronously
  // inside an effect body (react-hooks/set-state-in-effect).
  const [refreshKey, setRefreshKey] = useState(0);
  const refresh = useCallback(() => {
    setRefreshKey((k) => k + 1);
  }, []);

  useEffect(() => {
    if (!Number.isFinite(policyID)) return;
    let cancelled = false;
    setLoading(true); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch pattern
    setError(null);
    getAppControlPolicy(policyID)
      .then((result) => {
        if (!cancelled) setPolicy(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Unknown error");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [policyID, refreshKey]);

  if (!Number.isFinite(policyID)) {
    return (
      <>
        <PageHeader
          title="Application control"
          subtitle={
            <Link className="link-button" to="/app-control">
              ← Back to policies
            </Link>
          }
        />
        <EmptyState>Invalid policy id in URL.</EmptyState>
      </>
    );
  }

  const title = policy?.name ?? "Application control";
  const subtitle = (
    <>
      <Link className="link-button" to="/app-control">
        ← Back to policies
      </Link>
      {policy && (
        <>
          {" "}<span className="app-control__divider">·</span>{" "}
          version {policy.version}
          {" "}<span className="app-control__divider">·</span>{" "}
          assignments: <span className="app-control__assignment">all hosts</span>
        </>
      )}
    </>
  );

  const actions = (
    <Button
      variant="primary"
      onClick={() => { setAddOpen(true); }}
      disabled={!policy}
    >
      Add rule
    </Button>
  );

  const rules = policy?.rules ?? [];

  return (
    <>
      <PageHeader title={title} subtitle={subtitle} actions={actions} />
      {loading && <EmptyState>Loading policy...</EmptyState>}
      {error && !loading && <EmptyState>Error: {error}</EmptyState>}
      {!loading && !error && policy && (
        <>
          {policy.description && (
            <p className="app-control__description">{policy.description}</p>
          )}
          {rules.length === 0 ? (
            <EmptyState>
              This policy has no rules yet. Click <strong>Add rule</strong> to
              author the first one.
            </EmptyState>
          ) : (
            <RulesTable rules={rules} />
          )}
        </>
      )}
      {policy && (
        <AddRuleModal
          open={addOpen}
          policyID={policy.id}
          onClose={() => { setAddOpen(false); }}
          onCreated={() => {
            setAddOpen(false);
            refresh();
          }}
        />
      )}
    </>
  );
}

interface RulesTableProps {
  readonly rules: ApplicationControlRule[];
}

function RulesTable({ rules }: RulesTableProps) {
  return (
    <Table>
      <thead>
        <tr>
          <th>Type</th>
          <th>Identifier</th>
          <th>Severity</th>
          <th>Custom message</th>
          <th>Last modified</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {rules.map((rule) => (
          <tr key={rule.id}>
            <td>
              <Badge variant="neutral">{rule.rule_type}</Badge>
            </td>
            <td title={rule.identifier} className="app-control__identifier">
              {truncateIdentifier(rule.identifier)}
            </td>
            <td>
              <Badge variant={SEVERITY_VARIANTS[rule.severity] ?? "neutral"}>
                {rule.severity}
              </Badge>
            </td>
            <td>{rule.custom_msg ?? <span className="app-control__muted">—</span>}</td>
            <td>{new Date(rule.updated_at).toLocaleString()}</td>
            <td className="app-control__row-actions">
              {/* Edit / Disable / Delete are scaffolding only in
                  the demo cut. The disabled state + tooltip make
                  the roadmap visible without faking behaviour. */}
              <Button
                variant="text-link"
                size="small"
                disabled
                title="Editing rules is coming in the next release"
              >
                Edit
              </Button>
              <Button
                variant="text-link"
                size="small"
                disabled
                title={rule.enabled ? "Disabling rules is coming in the next release" : "Enabling rules is coming in the next release"}
              >
                {rule.enabled ? "Disable" : "Enable"}
              </Button>
              <Button
                variant="text-link"
                size="small"
                disabled
                title="Deleting rules is coming in the next release"
              >
                Delete
              </Button>
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
