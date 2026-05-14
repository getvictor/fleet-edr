import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listAppControlPolicies } from "../../api";
import type { ApplicationControlPolicy } from "../../types";
import { PageHeader } from "../ui/PageHeader";
import { Table, EmptyState } from "../ui/Table";
import { Button } from "../ui/Button";
import "./ApplicationControl.scss";

// PoliciesList renders the per-tenant Application Control policy
// roster. In the demo cut the seeded `Default` policy is the only
// row; multi-policy is post-demo, so the "New policy" button renders
// disabled with a "coming soon" tooltip — honest scaffolding rather
// than a 404. The list is the entry point for the camera-facing
// admin surface (demo beat #1).
export function PoliciesList() {
  const [policies, setPolicies] = useState<ApplicationControlPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch pattern
    setError(null);
    listAppControlPolicies()
      .then((result) => {
        if (!cancelled) setPolicies(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Unknown error");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  // ruleCount returns the number of rules attached to the policy. The
  // list endpoint omits the rules array so the count is unknown until
  // someone opens the detail page; show "—" rather than a fake 0 so
  // the admin knows they have to click in. Post-demo work adds a
  // rule_count aggregate to the list response.
  const ruleCount = (p: ApplicationControlPolicy): string =>
    p.rules ? String(p.rules.length) : "—";

  const newPolicyAction = (
    <Button
      variant="primary"
      disabled
      title="Multi-policy support coming in the next release"
    >
      New policy
    </Button>
  );

  return (
    <>
      <PageHeader
        title="Application control"
        subtitle="Rules the host extension consults on every exec"
        actions={newPolicyAction}
      />
      {loading && <EmptyState>Loading policies...</EmptyState>}
      {error && !loading && <EmptyState>Error: {error}</EmptyState>}
      {!loading && !error && policies.length === 0 && (
        <EmptyState>No policies found.</EmptyState>
      )}
      {!loading && !error && policies.length > 0 && (
        <Table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Rules</th>
              <th>Version</th>
              <th>Last modified</th>
              <th>Assignments</th>
            </tr>
          </thead>
          <tbody>
            {policies.map((p) => (
              <tr key={p.id}>
                <td>
                  <Link
                    className="link-button"
                    to={`/app-control/policies/${String(p.id)}`}
                    title="Open this policy's rules table"
                  >
                    {p.name}
                  </Link>
                  {p.description && (
                    <div className="app-control__row-secondary">{p.description}</div>
                  )}
                </td>
                <td>{ruleCount(p)}</td>
                <td>{p.version}</td>
                <td>{new Date(p.updated_at).toLocaleString()}</td>
                <td>
                  {/* Assignments are hardcoded "all-hosts" in the
                      demo cut; host-group editing is post-demo so
                      this column shows the literal value without an
                      action link. */}
                  <span className="app-control__assignment">all hosts</span>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </>
  );
}
