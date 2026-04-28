import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { fetchRuleDocs, type RuleDocEntry } from "../api";
import { PageHeader } from "./ui/PageHeader";
import { Table, EmptyState } from "./ui/Table";
import "./RuleDetail.scss";

// RuleDetail renders a single detection rule's documentation: behaviour,
// severity, ATT&CK mapping, configuration knobs, false-positive sources, and
// limitations. Data comes from /api/v1/admin/rules — the same JSON the
// markdown generator consumes — so this page can never drift from the
// generated docs/detection-rules.md.
//
// The /ui/coverage page links rule names here; if a future page lists alerts
// with rule IDs they should link here too. Unknown :ruleId renders an empty
// state pointing at the index, not a 404, so an old bookmark to a deleted
// rule still navigates somewhere actionable.

export function RuleDetail() {
  const { ruleId } = useParams<{ ruleId: string }>();
  const [entries, setEntries] = useState<RuleDocEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchRuleDocs()
      .then((rs) => { if (!cancelled) setEntries(rs); })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load rule docs");
      });
    return () => { cancelled = true; };
  }, []);

  const entry = useMemo(
    () => entries?.find((e) => e.id === ruleId) ?? null,
    [entries, ruleId],
  );

  return (
    <>
      <PageHeader
        title={entry ? entry.doc.title : "Detection rule"}
        subtitle={entry ? <code className="rule-detail__id">{entry.id}</code> : ruleId}
      />

      {error && <div className="form-error" role="alert">Error: {error}</div>}
      {!error && entries === null && <EmptyState>Loading rule documentation...</EmptyState>}

      {!error && entries !== null && !entry && (
        <EmptyState>
          Unknown rule <code>{ruleId}</code>. <Link to="/coverage">Back to coverage</Link>.
        </EmptyState>
      )}

      {entry && <RuleBody entry={entry} />}
    </>
  );
}

function RuleBody({ entry }: { entry: RuleDocEntry }) {
  const { doc, techniques } = entry;
  return (
    <div className="rule-detail">
      <p className="rule-detail__summary">{doc.summary}</p>

      <Table className="rule-detail__meta">
        <tbody>
          <tr>
            <th scope="row">Severity</th>
            <td><SeverityBadge severity={doc.severity} /></td>
          </tr>
          <tr>
            <th scope="row">ATT&amp;CK</th>
            <td>
              {techniques.length === 0
                ? <span className="rule-detail__muted">no mapping</span>
                : techniques.map((t, i) => (
                    <span key={t}>
                      {i > 0 && ", "}
                      <a
                        href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        <code>{t}</code>
                      </a>
                    </span>
                  ))}
            </td>
          </tr>
          <tr>
            <th scope="row">Event types</th>
            <td>
              {doc.event_types.map((t, i) => (
                <span key={t}>
                  {i > 0 && ", "}
                  <code>{t}</code>
                </span>
              ))}
            </td>
          </tr>
        </tbody>
      </Table>

      <h2>Description</h2>
      {/* Description is plain text from the Go side; we split on blank lines
          so paragraphs render. Keying on a stable derivation of the entry
          ID + paragraph index keeps React's reconciler happy without an
          array-index lint warning, and is fine here because the paragraph
          list is a deterministic function of the rule. */}
      {doc.description.split("\n\n").map((para, i) => (
        <p key={`${entry.id}-p${String(i)}`} className="rule-detail__para">{para}</p>
      ))}

      {doc.config && doc.config.length > 0 && (
        <>
          <h2>Configuration</h2>
          <Table className="rule-detail__config">
            <thead>
              <tr>
                <th>Env var</th>
                <th>Type</th>
                <th>Default</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {doc.config.map((c) => (
                <tr key={c.env_var}>
                  <td><code>{c.env_var}</code></td>
                  <td><code>{c.type}</code></td>
                  <td>{c.default === "" ? <span className="rule-detail__muted">(unset)</span> : <code>{c.default}</code>}</td>
                  <td>{c.description}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </>
      )}

      {doc.false_positives && doc.false_positives.length > 0 && (
        <>
          <h2>Known false-positive sources</h2>
          <ul className="rule-detail__list">
            {doc.false_positives.map((fp) => <li key={fp}>{fp}</li>)}
          </ul>
        </>
      )}

      {doc.limitations && doc.limitations.length > 0 && (
        <>
          <h2>Limitations</h2>
          <ul className="rule-detail__list">
            {doc.limitations.map((l) => <li key={l}>{l}</li>)}
          </ul>
        </>
      )}

      <p className="rule-detail__back">
        <Link to="/coverage">&larr; Back to ATT&amp;CK coverage</Link>
      </p>
    </div>
  );
}

// SeverityBadge picks a colour for the severity string. The four levels match
// the constants in server/detection/rule.go; an unknown level falls back to
// the neutral pill so a future fifth level renders something rather than
// crashing.
function SeverityBadge({ severity }: { severity: string }) {
  const klass = `rule-detail__sev rule-detail__sev--${severity}`;
  return <span className={klass}>{severity}</span>;
}
