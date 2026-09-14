import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { APP_CONTROL_RULE_PREFIX, listAlerts } from "../api";
import type { Alert } from "../types";
import { Badge } from "./ui/Badge";
import { severityBadgeVariant } from "./ui/severity";
import { EmptyState, Table } from "./ui/Table";
import { PageHeader } from "./ui/PageHeader";
import { useHostNames } from "./useHostNames";
import "./MonitorRecords.scss";

// The most records the page shows. A rule noisy enough to exceed it is already answered by the first page: the promote decision is
// about what the rule matches, and a hundred examples say that as well as a thousand.
const recordLimit = 100;

// MonitorRecords lists one rule's monitor records (issue #994): what the rule matched while it ran in monitor mode, so an operator deciding
// whether to promote it can read the matches rather than weigh a count. Reached from the rule's Observed figure on the detection-tuning
// page, which is where that decision is made.
//
// Deliberately not the Alerts page with a filter. A monitor record is not an alert: nobody was notified, it has no status to triage, and
// the Alerts page's status filter and Acknowledge / Resolve controls would all be wrong on it. Its own page carries none of them.
export function MonitorRecords() {
  const { ruleId = "" } = useParams<{ ruleId: string }>();
  const [records, setRecords] = useState<Alert[] | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const hostNames = useHostNames();

  useEffect(() => {
    let cancelled = false;
    setRecords(null); // eslint-disable-line react-hooks/set-state-in-effect -- data fetch pattern
    setError(null);
    // One past the limit, so "there are more" is proven by a row that exists rather than guessed from a full page: a rule with exactly
    // the limit's worth of records would otherwise be told some were left out.
    listAlerts({ disposition: "monitor", rule_id: ruleId, limit: recordLimit + 1 })
      .then((result) => {
        if (cancelled) return;
        setTruncated(result.length > recordLimit);
        setRecords(result.slice(0, recordLimit));
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Unknown error");
      });
    return () => { cancelled = true; };
  }, [ruleId]);

  return (
    <>
      <PageHeader title="Monitor records" subtitle={<code className="monitor-records__rule-id">{ruleId}</code>} />
      {/* Stated on the page rather than left to the Observed column's note, because this is where the two numbers meet: an operator
          arriving from a count of 40 and finding 3 records will otherwise read the difference as lost data. */}
      {ruleId.startsWith(APP_CONTROL_RULE_PREFIX) ? (
        // An application-control rule's records are the executables it let run in Detect mode. The detection wording below talks
        // about monitor mode and an Observed column this rule has neither of.
        <p className="monitor-records__explanation">
          What this application-control rule would have blocked while it ran in Detect mode, newest first. Each executable ran. These
          are not alerts: nobody was notified and there is nothing to triage. The same process running a matching executable again
          adds no record, so there can be fewer records than the would-block count on the policy page, which counts every run. Records
          also age out on the server&apos;s monitor-record retention window, 7 days by default.
        </p>
      ) : (
        <p className="monitor-records__explanation">
          What this rule matched while it ran in monitor mode, newest first. These are not alerts: nobody was notified and there is
          nothing to triage. A rule matching the same process again adds no record, so there can be fewer records than the rule&apos;s
          Observed count, which counts every match. Records also age out on the server&apos;s monitor-record retention window, 7 days
          by default, which can be set shorter or longer than the Observed window.
        </p>
      )}
      {records === null && error === null && <EmptyState>Loading monitor records...</EmptyState>}
      {error !== null && <EmptyState>Monitor records could not be loaded: {error}</EmptyState>}
      {records?.length === 0 && (
        <EmptyState>
          No monitor records for this rule. A rule can show matches with no records once they have aged out on the retention window, or if
          it matched before records were kept.
        </EmptyState>
      )}
      {records !== null && records.length > 0 && (
        <>
          {truncated && (
            <p className="monitor-records__limit">Showing the {String(recordLimit)} most recent records.</p>
          )}
          <Table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Host</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {records.map((r) => (
                <tr key={r.id}>
                  <td>
                    <Badge variant={severityBadgeVariant(r.severity)}>{r.severity}</Badge>
                  </td>
                  <td>
                    <Link className="link-button" to={`/alerts/${String(r.id)}`} title="Open this record's process tree">
                      {r.title}
                    </Link>
                    {/* The imported corpus's licence requires the author be credited wherever a match is displayed, and a monitor
                        record is a match as much as an alert is. */}
                    {r.origin && <div className="monitor-records__origin">{r.origin}</div>}
                  </td>
                  <td>
                    <Link className="link-button" to={`/hosts/${encodeURIComponent(r.host_id)}`} title={r.host_id}>
                      {hostNames.get(r.host_id) ?? r.host_id}
                    </Link>
                  </td>
                  <td>{new Date(r.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </>
      )}
    </>
  );
}
