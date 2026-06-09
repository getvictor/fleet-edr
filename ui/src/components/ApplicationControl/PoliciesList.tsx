import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listAppControlPolicies } from "../../api";
import type { ApplicationControlPolicy } from "../../types";
import { PageHeader } from "../ui/PageHeader";
import { Table, EmptyState } from "../ui/Table";
import { Button } from "../ui/Button";
import "./ApplicationControl.scss";

// PoliciesList renders the Application Control policy
// roster. In the demo cut the seeded `Default` policy is the only
// row; multi-policy is post-demo, so the "New policy" button renders
// disabled with a "coming soon" tooltip - honest scaffolding rather
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
  // someone opens the detail page; show "-" rather than a fake 0 so
  // the admin knows they have to click in. Post-demo work adds a
  // rule_count aggregate to the list response.
  const ruleCount = (p: ApplicationControlPolicy): string =>
    p.rules ? String(p.rules.length) : "-";

  // assignmentLabel formats the assignment_count column. The seed Default policy renders "1 host group" because its only
  // assignment row connects it to all-hosts; policies created without assignments render "no host groups" (an admin posture,
  // not a wire-shape error) and multi-group counts render with the plural form. Singular at exactly count == 1.
  const assignmentLabel = (count: number): string => {
    if (count === 0) return "no host groups";
    if (count === 1) return "1 host group";
    return `${String(count)} host groups`;
  };

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
                  {/* assignment_count is server-decorated via a correlated COUNT subquery on
                      app_control_assignments. The seed Default policy ships with 1 (its assignment
                      to all-hosts); policies created via the create endpoint land at 0 until an
                      assignment is added, and Phase B's multi-group editing grows the value.
                      Singular / plural / zero handled inline so an unwired policy reads sensibly. */}
                  <span className="app-control__assignment">{assignmentLabel(p.assignment_count)}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </>
  );
}
